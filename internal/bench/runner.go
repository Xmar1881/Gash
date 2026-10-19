// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// RunOptions configures one benchmark run.
type RunOptions struct {
	DatasetPath     string
	OutDir          string
	RepoDir         string
	GashBin         string
	NucleiBin       string
	Tools           []string
	AllowNonLab     bool
	NoBrowserVerify bool
	BaselinePath    string
	Gate            GateThresholds
	Logf            func(format string, args ...any)
}

// Runner orchestrates verification, runs, scoring and reporting.
type Runner struct {
	opts RunOptions
	log  func(string, ...any)
}

// NewRunner builds a runner with defaults.
func NewRunner(opts RunOptions) *Runner {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if len(opts.Tools) == 0 {
		opts.Tools = []string{"gash", "nuclei"}
	}
	return &Runner{opts: opts, log: opts.Logf}
}

func (r *Runner) wantTool(name string) bool {
	for _, t := range r.opts.Tools {
		if t == name {
			return true
		}
	}
	return false
}

// Run executes the full benchmark and writes the report directory.
func (r *Runner) Run(ctx context.Context) (*Report, error) {
	started := time.Now().UTC()
	ds, err := LoadDataset(r.opts.DatasetPath)
	if err != nil {
		return nil, err
	}
	if err := Validate(ds, r.opts.AllowNonLab); err != nil {
		return nil, err
	}
	r.log("dataset %s loaded: %d target(s), %d scenario(s)", ds.Name, len(ds.Targets), len(ds.Scenarios))

	lab, cleanupLab, err := r.prepareLab(ctx, ds)
	if err != nil {
		return nil, err
	}
	defer cleanupLab()

	verifier := NewVerifier()
	marker := NewMarker()
	verifications := map[string]Verification{}
	var unverified []UnverifiedRow
	r.log("verifying %d scenarios independently (marker %s)", len(ds.Scenarios), marker)
	for i := range ds.Scenarios {
		sc := &ds.Scenarios[i]
		if r.opts.NoBrowserVerify && sc.Verify.Kind == VerifyBrowserExec {
			verifications[sc.ID] = Verification{Kind: sc.Verify.Kind, Error: "browser verification disabled by --no-browser-verify"}
		} else {
			verifications[sc.ID] = verifier.VerifyScenario(ctx, ds, sc, marker)
		}
		v := verifications[sc.ID]
		r.log("verify %-28s %-14s verified=%v %s", sc.ID, sc.Verify.Kind, v.Verified, firstNonEmpty(v.Error, v.Detail))
		if !v.Verified {
			unverified = append(unverified, UnverifiedRow{Scenario: sc.ID, Kind: sc.Verify.Kind, Reason: firstNonEmpty(v.Error, "verification failed")})
		}
	}

	tmpDir, err := os.MkdirTemp("", "gash-bench-")
	if err != nil {
		return nil, fmt.Errorf("bench: temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	gashBin, err := r.resolveGashBin()
	if err != nil {
		return nil, err
	}

	var gashRuns []ToolRun
	var gashFindings []NormalizedFinding
	gashVersion := gashBuildVersion(gashBin)

	nucleiBin, nucleiVersion, nucleiErr := DetectNuclei(r.opts.NucleiBin)
	nucleiAvailable := r.wantTool("nuclei") && nucleiErr == nil
	var nucleiRuns []ToolRun
	var nucleiFindings []NormalizedFinding
	if r.wantTool("nuclei") && nucleiErr != nil {
		r.log("nuclei unavailable: %v", nucleiErr)
	}

	groups := r.runGroups(ds)
	gashTimeout := parseDurationDefault(ds.Gash.Timeout, 3*time.Minute)
	nucleiTimeout := parseDurationDefault(ds.Nuclei.Timeout, 3*time.Minute)

	for _, g := range groups {
		if r.wantTool("gash") {
			args := append([]string{}, ds.Gash.Args...)
			if !hasFlag(args, "--scope") {
				if host := hostOf(g.baseURL); host != "" {
					args = append(args, "--scope", host)
				}
			}
			authArgs, err := authFlags(g.target, g.auth)
			if err != nil {
				return nil, err
			}
			args = append(args, authArgs...)
			var before int64
			if lab != nil {
				before = lab.Total()
			}
			r.log("gash run target=%s auth=%s", g.baseURL, g.auth)
			run, findings := RunGash(ctx, gashBin, r.opts.RepoDir, g.baseURL, g.auth, args, gashTimeout, tmpDir)
			if lab != nil {
				obs := lab.Total() - before
				run.ObservedRequests = &obs
			}
			if run.Error != "" {
				r.log("gash run error: %s", run.Error)
			}
			gashRuns = append(gashRuns, *run)
			gashFindings = append(gashFindings, findings...)
		}
		if nucleiAvailable {
			authHeader, err := authHeaderFor(g.target, g.auth)
			if err != nil {
				return nil, err
			}
			var before int64
			if lab != nil {
				before = lab.Total()
			}
			r.log("nuclei run target=%s auth=%s", g.baseURL, g.auth)
			run, findings := RunNuclei(ctx, nucleiBin, g.baseURL, authHeader, ds.Nuclei, nucleiTimeout)
			if lab != nil {
				obs := lab.Total() - before
				run.ObservedRequests = &obs
			}
			if run.Error != "" {
				r.log("nuclei run error: %s", run.Error)
			}
			nucleiRuns = append(nucleiRuns, *run)
			nucleiFindings = append(nucleiFindings, findings...)
		}
	}

	rep := &Report{
		SchemaVersion: ReportSchemaVersion,
		GeneratedAt:   started.Format(time.RFC3339),
		Dataset: DatasetSummary{
			Name: ds.Name, Kind: ds.Kind, Path: ds.Path, SHA256: ds.SHA256,
			ScenarioCount: len(ds.Scenarios), TargetCount: len(ds.Targets),
		},
		Tools:    map[string]*ToolResult{},
		Outcomes: map[string][]Outcome{},
	}

	gashOutcomes, gashUnmatched, gashExcluded := BuildOutcomes(ds, "gash", true, gashFindings, verifications)
	rep.Tools["gash"] = buildToolResult("gash", true, "", gashVersion, gashRuns, gashFindings, gashOutcomes, gashUnmatched, gashExcluded, ds)
	rep.Outcomes["gash"] = gashOutcomes

	if r.wantTool("nuclei") {
		if nucleiAvailable {
			nuOutcomes, nuUnmatched, nuExcluded := BuildOutcomes(ds, "nuclei", true, nucleiFindings, verifications)
			rep.Tools["nuclei"] = buildToolResult("nuclei", true, "", nucleiVersion, nucleiRuns, nucleiFindings, nuOutcomes, nuUnmatched, nuExcluded, ds)
			rep.Outcomes["nuclei"] = nuOutcomes
			rep.UnmatchedFindings = append(rep.UnmatchedFindings, nuUnmatched...)
			rep.ExcludedFindings = append(rep.ExcludedFindings, nuExcluded...)
		} else {
			nuOutcomes, _, _ := BuildOutcomes(ds, "nuclei", false, nil, verifications)
			rep.Tools["nuclei"] = &ToolResult{Available: false, Reason: nucleiErr.Error(), Runs: []ToolRun{}, ByCategory: map[string]Score{}, Score: ScoreOutcomes(nuOutcomes)}
			rep.Outcomes["nuclei"] = nuOutcomes
		}
	}

	rep.CrossTool = BuildCrossTool(rep.Outcomes)
	rep.Unverified = unverified
	rep.UnmatchedFindings = append(gashUnmatched, rep.UnmatchedFindings...)
	rep.ExcludedFindings = append(gashExcluded, rep.ExcludedFindings...)
	rep.BuildMissed()
	rep.Manifest = r.buildManifest(started, ds, lab, gashBin, gashVersion, nucleiBin, nucleiVersion, rep)
	rep.Limitations = r.limitations(ds, lab, nucleiAvailable, nucleiErr, unverified, rep)

	if r.opts.BaselinePath != "" {
		base, err := LoadBaseline(r.opts.BaselinePath)
		if err != nil {
			r.log("baseline load failed: %v", err)
			gate := GateResult{Passed: false, Reasons: []string{err.Error()}}
			rep.Gate = &gate
		} else {
			cur, err := BaselineFromReport(rep, "gash")
			if err != nil {
				gate := GateResult{Passed: false, Reasons: []string{err.Error()}}
				rep.Gate = &gate
			} else {
				gate := CompareBaseline(base, cur, r.opts.Gate)
				rep.Gate = &gate
			}
		}
	}

	outDir := r.opts.OutDir
	if outDir == "" {
		outDir = filepath.Join("bench", "results", started.Format("20060102-150405"))
	}
	rep.Manifest.Environment["report_dir"] = outDir
	files, err := rep.WriteDir(outDir)
	if err != nil {
		return rep, err
	}
	r.log("report written to %s", outDir)
	for name, path := range files {
		r.log("  %s -> %s", name, path)
	}
	return rep, nil
}

type runGroup struct {
	target  *Target
	baseURL string
	auth    string
}

func (r *Runner) runGroups(ds *Dataset) []runGroup {
	order := []string{AuthNone, AuthUserA, AuthUserB, AuthMatrix}
	used := map[string]map[string]bool{}
	for i := range ds.Scenarios {
		sc := &ds.Scenarios[i]
		t, err := ds.ScenarioTarget(sc)
		if err != nil {
			continue
		}
		if used[t.ID] == nil {
			used[t.ID] = map[string]bool{}
		}
		used[t.ID][sc.Auth] = true
	}
	var groups []runGroup
	for i := range ds.Targets {
		t := &ds.Targets[i]
		for _, auth := range order {
			if used[t.ID][auth] {
				groups = append(groups, runGroup{target: t, baseURL: t.BaseURL, auth: auth})
			}
		}
	}
	return groups
}

func (r *Runner) prepareLab(ctx context.Context, ds *Dataset) (*FixtureLab, func(), error) {
	if ds.Kind == KindFixtures {
		lab, err := StartFixtureLab()
		if err != nil {
			return nil, nil, err
		}
		for i := range ds.Targets {
			ds.Targets[i].BaseURL = strings.ReplaceAll(ds.Targets[i].BaseURL, FixtureBasePlaceholder, lab.URL())
		}
		r.log("fixture lab started at %s", lab.URL())
		return lab, func() { _ = lab.Close() }, nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for i := range ds.Targets {
		u := ds.Targets[i].BaseURL
		if u == "" || strings.Contains(u, FixtureBasePlaceholder) {
			return nil, nil, fmt.Errorf("bench: compose dataset target %q has unresolved base_url %q", ds.Targets[i].ID, u)
		}
		resp, err := client.Get(u)
		if err != nil {
			return nil, nil, fmt.Errorf("bench: lab target %s unreachable at %s: %w\nstart the lab first: gash bench lab up (requires docker)", ds.Targets[i].ID, u, err)
		}
		resp.Body.Close()
	}
	return nil, func() {}, nil
}

func (r *Runner) resolveGashBin() (string, error) {
	if r.opts.GashBin != "" && r.opts.GashBin != "auto" {
		if _, err := os.Stat(r.opts.GashBin); err != nil {
			return "", fmt.Errorf("bench: gash binary %s: %w", r.opts.GashBin, err)
		}
		return r.opts.GashBin, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("bench: locate self: %w", err)
	}
	return exe, nil
}

func buildToolResult(tool string, available bool, reason, version string, runs []ToolRun, findings []NormalizedFinding, outcomes []Outcome, unmatched, excluded []NormalizedFinding, ds *Dataset) *ToolResult {
	res := &ToolResult{
		Available:  available,
		Reason:     reason,
		Version:    version,
		Runs:       runs,
		Findings:   len(findings),
		Score:      ScoreOutcomes(outcomes),
		ByCategory: ScoreByCategory(outcomes),
		XSS:        ScoreXSS(ds, outcomes),
		Unmatched:  len(unmatched),
		Excluded:   len(excluded),
	}
	var reported, observed, cpu, rss *int64
	var tentative int
	for _, run := range runs {
		res.DurationMS += run.DurationMS
		tentative += run.TentativeTotal
		if run.ReportedRequests != nil {
			v := *run.ReportedRequests
			if reported == nil {
				reported = new(int64)
			}
			*reported += v
		}
		if run.ObservedRequests != nil {
			v := *run.ObservedRequests
			if observed == nil {
				observed = new(int64)
			}
			*observed += v
		}
		if run.CPUTimeMS != nil {
			v := *run.CPUTimeMS
			if cpu == nil || v > *cpu {
				cpu = &v
			}
		}
		if run.MaxRSSKB != nil {
			v := *run.MaxRSSKB
			if rss == nil || v > *rss {
				rss = &v
			}
		}
	}
	res.ReportedRequests = reported
	res.ObservedRequests = observed
	res.CPUTimeMS = cpu
	res.MaxRSSKB = rss
	res.TentativeTotal = tentative
	return res
}

func (r *Runner) buildManifest(started time.Time, ds *Dataset, lab *FixtureLab, gashBin, gashVersion, nucleiBin, nucleiVersion string, rep *Report) Manifest {
	finished := time.Now().UTC()
	m := Manifest{
		StartedAt:     started.Format(time.RFC3339),
		FinishedAt:    finished.Format(time.RFC3339),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		GoVersion:     runtime.Version(),
		DatasetPath:   ds.Path,
		DatasetSHA256: ds.SHA256,
		GashBin:       gashBin,
		GashVersion:   gashVersion,
		GashSHA256:    fileSHA256(gashBin),
		NucleiBin:     nucleiBin,
		NucleiVersion: nucleiVersion,
		Environment:   map[string]string{},
	}
	if commit, dirty, err := gitInfo(r.opts.RepoDir); err == nil {
		m.GitCommit = commit
		m.GitDirty = dirty
	}
	if lab != nil {
		m.FixtureLab = &LabManifest{Kind: ds.Kind, URL: lab.URL(), TotalObserved: lab.Total(), PerPath: lab.Snapshot()}
	}
	if gash := rep.Tools["gash"]; gash != nil && gash.Available {
		m.Conditions = append(m.Conditions,
			fmt.Sprintf("gash runs: %d (targets x auth groups); args template: %s", len(gash.Runs), strings.Join(ds.Gash.Args, " ")),
			"gash has a total request budget and per-plugin timeout; the dataset pins them (see run commands)")
	}
	if nuc, ok := rep.Tools["nuclei"]; ok && nuc != nil && nuc.Available {
		m.Conditions = append(m.Conditions,
			fmt.Sprintf("nuclei runs: %d; tags: %s; rate-limit: %d; wall-clock timeout: %s",
				len(nuc.Runs), strings.Join(ds.Nuclei.Tags, ","), ds.Nuclei.RateLimit, ds.Nuclei.Timeout),
			"nuclei cannot cap total requests (upstream limitation); equalized by wall-clock timeout plus rate limit")
	}
	m.Conditions = append(m.Conditions,
		"both tools ran sequentially against the same lab base URLs with their own auth headers",
		"fixture lab observed request counts are counted by the lab itself (independent of tool self-reporting)")
	return m
}

func (r *Runner) limitations(ds *Dataset, lab *FixtureLab, nucleiAvailable bool, nucleiErr error, unverified []UnverifiedRow, rep *Report) []string {
	var out []string
	if !r.wantTool("nuclei") {
		out = append(out, "nuclei comparison skipped by --tool selection")
	} else if !nucleiAvailable && nucleiErr != nil {
		out = append(out, "nuclei unavailable on this machine: "+nucleiErr.Error()+"; the comparison cannot run here and is reported as N/A, never as zero success")
	}
	if lab == nil {
		out = append(out, "compose lab runs require a docker runtime; if the lab was not started manually no compose scenarios can execute")
	}
	if len(unverified) > 0 {
		out = append(out, fmt.Sprintf("%d scenario(s) could not be independently verified and are excluded from scoring (see unverified_scenarios)", len(unverified)))
	}
	if browserVerifyUnavailable() {
		out = append(out, "browser execution verification requires a -tags deep build with Chrome; DOM XSS scenarios stay unverified and are excluded from scoring in this build")
	}
	if runtime.GOOS != "linux" {
		out = append(out, "CPU/memory sampling of child processes is only implemented on Linux (/proc); reported as N/A on this platform")
	}
	out = append(out,
		fmt.Sprintf("scoring is limited to the dataset's declared scenario classes (%d scenarios); findings outside them are listed, not scored", len(ds.Scenarios)))
	if len(ds.UnscoredPlugins) > 0 || len(ds.UnscoredRules) > 0 {
		out = append(out, "dataset declares out-of-scope plugins/rules; their findings are listed under excluded_findings, not scored")
	}
	if rep != nil && rep.Tools["gash"] != nil && rep.Tools["gash"].Score.NotRun > 0 {
		out = append(out, fmt.Sprintf("%d gash outcome(s) not-run (tool error/timeout); see runs", rep.Tools["gash"].Score.NotRun))
	}
	return out
}

func authFlags(t *Target, auth string) ([]string, error) {
	switch auth {
	case "", AuthNone:
		return nil, nil
	case AuthUserA:
		v, ok := t.Auth[AuthUserA]
		if !ok || v == "" {
			return nil, fmt.Errorf("bench: target %s lacks auth %s", t.ID, AuthUserA)
		}
		return []string{"--auth-header", v}, nil
	case AuthUserB:
		v, ok := t.Auth[AuthUserB]
		if !ok || v == "" {
			return nil, fmt.Errorf("bench: target %s lacks auth %s", t.ID, AuthUserB)
		}
		return []string{"--auth-header", v}, nil
	case AuthMatrix:
		a, b := t.Auth[AuthUserA], t.Auth[AuthUserB]
		if a == "" || b == "" {
			return nil, fmt.Errorf("bench: target %s lacks user-a/user-b for matrix auth", t.ID)
		}
		return []string{"--auth-user-a", a, "--auth-user-b", b}, nil
	}
	return nil, fmt.Errorf("bench: unknown auth group %q", auth)
}

func authHeaderFor(t *Target, auth string) (string, error) {
	switch auth {
	case "", AuthNone:
		return "", nil
	case AuthUserA, AuthMatrix:
		if v := t.Auth[AuthUserA]; v != "" {
			return v, nil
		}
		return "", fmt.Errorf("bench: target %s lacks auth %s", t.ID, AuthUserA)
	case AuthUserB:
		if v := t.Auth[AuthUserB]; v != "" {
			return v, nil
		}
		return "", fmt.Errorf("bench: target %s lacks auth %s", t.ID, AuthUserB)
	}
	return "", fmt.Errorf("bench: unknown auth group %q", auth)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func parseDurationDefault(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func gashBuildVersion(bin string) string {
	if exe, err := os.Executable(); err == nil && exe == bin {
		if info, ok := debug.ReadBuildInfo(); ok {
			return info.Main.Version
		}
	}
	return ""
}

func gitInfo(repoDir string) (string, bool, error) {
	if repoDir == "" {
		return "", false, fmt.Errorf("no repo dir")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	commitCmd := exec.CommandContext(ctx, "git", "-C", repoDir, "rev-parse", "HEAD")
	commitOut, err := commitCmd.Output()
	if err != nil {
		return "", false, err
	}
	statusCmd := exec.CommandContext(ctx, "git", "-C", repoDir, "status", "--porcelain")
	statusOut, err := statusCmd.Output()
	dirty := err == nil && len(strings.TrimSpace(string(statusOut))) > 0
	return strings.TrimSpace(string(commitOut)), dirty, nil
}
