// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// NormalizedFinding is one tool finding reduced to the benchmark vocabulary.
type NormalizedFinding struct {
	Tool         string   `json:"tool"`
	Target       string   `json:"target"`
	Path         string   `json:"path"`
	Auth         string   `json:"auth"`
	PluginID     string   `json:"plugin_id,omitempty"`
	TemplateID   string   `json:"template_id,omitempty"`
	RuleID       string   `json:"rule_id,omitempty"`
	Title        string   `json:"title,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
	EvidenceType string   `json:"evidence_type,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

// ToolRun records one tool invocation with its measured conditions.
type ToolRun struct {
	Tool             string   `json:"tool"`
	Target           string   `json:"target"`
	Auth             string   `json:"auth"`
	Command          []string `json:"command"`
	DurationMS       int64    `json:"duration_ms"`
	TimedOut         bool     `json:"timed_out"`
	ExitCode         int      `json:"exit_code"`
	Error            string   `json:"error,omitempty"`
	Findings         int      `json:"findings"`
	TentativeTotal   int      `json:"tentative_total,omitempty"`
	ReportedRequests *int64   `json:"reported_requests,omitempty"`
	ObservedRequests *int64   `json:"observed_requests,omitempty"`
	CPUTimeMS        *int64   `json:"cpu_time_ms,omitempty"`
	MaxRSSKB         *int64   `json:"max_rss_kb,omitempty"`
}

type gashScanOutput struct {
	Target   string `json:"target"`
	Findings []struct {
		ID           string            `json:"id"`
		RuleID       string            `json:"rule_id"`
		Title        string            `json:"title"`
		Severity     string            `json:"severity"`
		Confidence   string            `json:"confidence"`
		Target       string            `json:"target"`
		PluginID     string            `json:"plugin_id"`
		Fingerprint  string            `json:"fingerprint"`
		EvidenceType string            `json:"evidence_type"`
		Evidence     map[string]string `json:"evidence"`
	} `json:"findings"`
	Stats map[string]int64 `json:"stats"`
}

// RunGash executes one Gash scan run and parses the JSON report.
func RunGash(ctx context.Context, bin, repoDir, target, auth string, args []string, timeout time.Duration, tmpDir string) (*ToolRun, []NormalizedFinding) {
	run := &ToolRun{Tool: "gash", Target: target, Auth: redactAuth(auth)}
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	// Default scoring uses the tool's normal report visibility: tentative
	// candidates stay unscored unless the dataset explicitly opts in with
	// --show-tentative. The total (firm+tentative) is still recorded.
	outPath := filepath.Join(tmpDir, fmt.Sprintf("gash-%s.json", sanitize(target+auth)))
	cmdArgs := []string{"scan", "--target", target, "--format", "json", "--output", outPath}
	cmdArgs = append(cmdArgs, args...)
	run.Command = redactedCommand(bin, cmdArgs)

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin, cmdArgs...)
	cmd.Dir = repoDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Start()
	if err != nil {
		run.Error = err.Error()
		run.DurationMS = time.Since(start).Milliseconds()
		return run, nil
	}
	watcher, _ := startProcWatcher(cmd.Process.Pid)
	err = cmd.Wait()
	run.DurationMS = time.Since(start).Milliseconds()
	if watcher != nil {
		if sample := watcher.Stop(); sample != nil {
			run.CPUTimeMS = &sample.CPUTimeMS
			run.MaxRSSKB = &sample.MaxRSSKB
		}
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		run.TimedOut = true
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			run.ExitCode = exitErr.ExitCode()
		} else {
			run.ExitCode = -1
		}
		if !run.TimedOut {
			msg := strings.TrimSpace(stderr.String())
			if len(msg) > 400 {
				msg = msg[:400]
			}
			run.Error = fmt.Sprintf("gash exited: %v: %s", err, msg)
			return run, nil
		}
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		run.Error = "gash report unreadable: " + err.Error()
		return run, nil
	}
	var out gashScanOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		run.Error = "gash report parse: " + err.Error()
		return run, nil
	}
	run.Findings = len(out.Findings)
	if v, ok := out.Stats["findings"]; ok && int(v) > run.Findings {
		run.TentativeTotal = int(v) - run.Findings
	}
	if v, ok := out.Stats["http_requests"]; ok {
		run.ReportedRequests = &v
	}
	findings := make([]NormalizedFinding, 0, len(out.Findings))
	for _, f := range out.Findings {
		findings = append(findings, NormalizedFinding{
			Tool:         "gash",
			Target:       f.Target,
			Path:         normalizePath(f.Target),
			Auth:         auth,
			PluginID:     f.PluginID,
			RuleID:       f.RuleID,
			Title:        f.Title,
			Severity:     f.Severity,
			Confidence:   f.Confidence,
			EvidenceType: f.EvidenceType,
			Fingerprint:  f.Fingerprint,
		})
	}
	return run, findings
}

var (
	nucleiVersionLineRe = regexp.MustCompile(`(?i)nuclei\s+engine\s+version\s*:\s*v?(\d+\.\d+[\.\d]*)`)
	nucleiVersionRe     = regexp.MustCompile(`(?i)(?:engine\s+version\s*:\s*|[^a-z0-9])v(\d+\.\d+[\.\d]*)`)
)

// DetectNuclei resolves the nuclei binary and its version.
func DetectNuclei(bin string) (string, string, error) {
	if bin == "" {
		bin = "nuclei"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", "", fmt.Errorf("nuclei not found in PATH (install from https://github.com/projectdiscovery/nuclei/releases): %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	if err != nil {
		return path, "", fmt.Errorf("nuclei -version: %w: %s", err, strings.TrimSpace(string(out)))
	}
	version := versionFromText(string(out), "nuclei")
	return path, version, nil
}

func versionFromText(text, fallback string) string {
	if m := nucleiVersionLineRe.FindStringSubmatch(text); len(m) > 1 {
		return "v" + m[1]
	}
	if m := nucleiVersionRe.FindStringSubmatch(text); len(m) > 1 {
		return "v" + m[1]
	}
	return fallback + " (version unknown)"
}

type nucleiInfo struct {
	Name     string          `json:"name"`
	Severity string          `json:"severity"`
	Tags     json.RawMessage `json:"tags"`
}

type nucleiLine struct {
	TemplateID string     `json:"template-id"`
	MatchedAt  string     `json:"matched-at"`
	Host       string     `json:"host"`
	Type       string     `json:"type"`
	Info       nucleiInfo `json:"info"`
}

// RunNuclei executes one nuclei run and parses the JSONL stream.
func RunNuclei(ctx context.Context, bin, target, auth string, seeds []string, cfg NucleiConfig, timeout time.Duration) (*ToolRun, []NormalizedFinding) {
	run := &ToolRun{Tool: "nuclei", Target: target, Auth: redactAuth(auth)}
	rate := cfg.RateLimit
	if rate <= 0 {
		rate = 50
	}
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	args := []string{"-jsonl", "-silent", "-no-color", "-disable-update-check",
		"-rate-limit", fmt.Sprintf("%d", rate), "-timeout", "10", "-u", target}
	for _, seed := range seeds {
		if strings.TrimSpace(seed) != "" {
			args = append(args, "-u", seed)
		}
	}
	if len(cfg.Tags) > 0 {
		args = append(args, "-tags", strings.Join(cfg.Tags, ","))
	}
	if auth != "" {
		args = append(args, "-H", auth)
	}
	args = append(args, cfg.Args...)
	run.Command = redactedCommand(bin, args)

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		run.Error = err.Error()
		run.DurationMS = time.Since(start).Milliseconds()
		return run, nil
	}
	watcher, _ := startProcWatcher(cmd.Process.Pid)
	err := cmd.Wait()
	run.DurationMS = time.Since(start).Milliseconds()
	if watcher != nil {
		if sample := watcher.Stop(); sample != nil {
			run.CPUTimeMS = &sample.CPUTimeMS
			run.MaxRSSKB = &sample.MaxRSSKB
		}
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		run.TimedOut = true
	}
	if err != nil && !run.TimedOut {
		if exitErr, ok := err.(*exec.ExitError); ok {
			run.ExitCode = exitErr.ExitCode()
		} else {
			run.ExitCode = -1
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		run.Error = fmt.Sprintf("nuclei exited: %v: %s", err, msg)
		return run, nil
	}
	if req, ok := parseNucleiRequests(stderr.String()); ok {
		run.ReportedRequests = &req
	}
	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var findings []NormalizedFinding
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var nl nucleiLine
		if err := json.Unmarshal([]byte(line), &nl); err != nil {
			continue
		}
		at := nl.MatchedAt
		if at == "" {
			at = nl.Host
		}
		findings = append(findings, NormalizedFinding{
			Tool:       "nuclei",
			Target:     at,
			Path:       normalizePath(at),
			Auth:       auth,
			TemplateID: nl.TemplateID,
			Title:      nl.Info.Name,
			Severity:   nl.Info.Severity,
			Tags:       parseNucleiTags(nl.Info.Tags),
		})
	}
	run.Findings = len(findings)
	return run, findings
}

var nucleiRequestsRe = regexp.MustCompile(`Requests:\s*(\d+)`)

func parseNucleiRequests(stderr string) (int64, bool) {
	matches := nucleiRequestsRe.FindAllStringSubmatch(stderr, -1)
	if len(matches) == 0 {
		return 0, false
	}
	var v int64
	_, err := fmt.Sscanf(matches[len(matches)-1][1], "%d", &v)
	return v, err == nil
}

func parseNucleiTags(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil && single != "" {
		parts := strings.Split(single, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	return nil
}

func normalizePath(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Path == "" {
		return trimTrailingSlash(strings.Split(strings.TrimSpace(raw), "?")[0])
	}
	if frag := u.Fragment; strings.HasPrefix(frag, "/") || strings.HasPrefix(frag, "!") {
		route := strings.TrimPrefix(frag, "!")
		route, _, _ = strings.Cut(route, "?")
		if route == "" {
			route = "/"
		}
		if !strings.HasPrefix(route, "/") {
			route = "/" + route
		}
		base := strings.TrimSuffix(u.Path, "/")
		if base == "" {
			return trimTrailingSlash(route)
		}
		return trimTrailingSlash(base + route)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return trimTrailingSlash(path)
}

// DedupeNormalizedFindings collapses findings repeated across auth runs while
// preserving the strongest evidence tier. Exact fingerprints are the primary
// identity; tools without them fall back to path/title.
func DedupeNormalizedFindings(in []NormalizedFinding) []NormalizedFinding {
	out := make([]NormalizedFinding, 0, len(in))
	index := make(map[string]int, len(in))
	for _, f := range in {
		key := normalizedFindingKey(f)
		if pos, ok := index[key]; ok {
			if confidenceRank(f.Confidence) > confidenceRank(out[pos].Confidence) {
				out[pos] = f
			}
			continue
		}
		index[key] = len(out)
		out = append(out, f)
	}
	return out
}

func normalizedFindingKey(f NormalizedFinding) string {
	base := strings.ToLower(strings.TrimSpace(f.Tool)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Target)) + "|" +
		f.PluginID + "|" + f.RuleID + "|" + f.TemplateID
	if f.Fingerprint != "" {
		return base + "|fp:" + f.Fingerprint
	}
	return base + "|" + normalizePath(f.Path) + "|" + strings.ToLower(strings.TrimSpace(f.Title))
}

func confidenceRank(confidence string) int {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "confirmed":
		return 3
	case "firm":
		return 2
	case "tentative":
		return 1
	default:
		return 0
	}
}

func trimTrailingSlash(path string) string {
	if len(path) > 1 {
		return strings.TrimRight(path, "/")
	}
	return path
}

func redactAuth(auth string) string {
	if strings.TrimSpace(auth) == "" {
		return ""
	}
	return "<redacted>"
}

func redactedCommand(bin string, args []string) []string {
	out := append([]string{bin}, args...)
	for i := 1; i < len(out); i++ {
		switch out[i] {
		case "--auth-header", "--auth-user-a", "--auth-user-b", "-H":
			if i+1 < len(out) {
				out[i+1] = "<redacted>"
				i++
			}
		}
	}
	return out
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
