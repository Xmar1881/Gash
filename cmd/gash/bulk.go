// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/reporter"
)

// BulkSummary toplu tarama sonuç özetidir.
type BulkSummary struct {
	ScanTime        string              `json:"scan_time"`
	TotalTargets    int                 `json:"total_targets"`
	Completed       int                 `json:"completed"`
	Skipped         int                 `json:"skipped"`
	Failed          int                 `json:"failed"`
	TotalRequests   int64               `json:"total_requests"`
	BudgetExhausted bool                `json:"budget_exhausted"`
	Targets         []BulkTargetSummary `json:"targets"`
}

// BulkTargetSummary hedef başına tarama özetidir.
type BulkTargetSummary struct {
	Target        string            `json:"target"`
	Status        string            `json:"status"` // "completed", "skipped_resume", "failed", "budget_exhausted"
	FindingsCount int               `json:"findings_count"`
	HighCount     int               `json:"high_count"`
	MediumCount   int               `json:"medium_count"`
	LowCount      int               `json:"low_count"`
	InfoCount     int               `json:"info_count"`
	Reports       map[string]string `json:"reports,omitempty"`
	Error         string            `json:"error,omitempty"`
	Requests      int64             `json:"requests"`
}

// readTargetFile reads target URLs from a file, supporting # comments and blank lines.
func readTargetFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scan: --target-file okunamadı %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Support inline comments: "http://example.com # prod target"
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: --target-file okuma hatası %q: %w", path, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("scan: --target-file %q içinde geçerli hedef bulunamadı", path)
	}
	return targets, nil
}

var safeFilenameRegex = regexp.MustCompile(`[^a-zA-Z0-9.-]+`)

// targetReportBaseName converts a target URL into a deterministic filesystem-safe filename base.
func targetReportBaseName(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		s := safeFilenameRegex.ReplaceAllString(rawURL, "_")
		s = strings.Trim(s, "_")
		if s == "" {
			return "target"
		}
		return s
	}
	host := strings.ReplaceAll(u.Host, ":", "_")
	path := strings.Trim(u.Path, "/")
	if path != "" {
		cleanPath := safeFilenameRegex.ReplaceAllString(path, "_")
		cleanPath = strings.Trim(cleanPath, "_")
		if cleanPath != "" {
			return host + "_" + cleanPath
		}
	}
	return host
}

// isTargetAlreadyScanned checks if report files already exist for the target under outputDir.
func isTargetAlreadyScanned(outputDir, baseName string, formats []string) bool {
	for _, f := range formats {
		p := filepath.Join(outputDir, baseName+"."+f)
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return true
		}
	}
	// Fallback check for .json
	p := filepath.Join(outputDir, baseName+".json")
	if st, err := os.Stat(p); err == nil && st.Size() > 0 {
		return true
	}
	return false
}

// runBulkScan executes a scan across multiple targets from targetFile.
func runBulkScan(
	ctx context.Context,
	cmd *cobra.Command,
	reg *plugin.Registry,
	cfg engine.Config,
	records map[string]loader.TrustRecord,
	targetFile string,
	outputDir string,
	resume bool,
	formats []string,
	failLevel string,
	showTentative bool,
) error {
	targets, err := readTargetFile(targetFile)
	if err != nil {
		return err
	}
	if strings.TrimSpace(outputDir) == "" {
		outputDir = "reports"
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("scan: --output-dir oluşturulamadı %q: %w", outputDir, err)
	}

	var parsedProxy *url.URL
	if strings.TrimSpace(cfg.ProxyURL) != "" {
		var err error
		parsedProxy, err = url.Parse(strings.TrimSpace(cfg.ProxyURL))
		if err != nil {
			return fmt.Errorf("scan: geçersiz proxy URL %q: %w", cfg.ProxyURL, err)
		}
	}
	if len(cfg.Scope) == 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "notice: no --scope set: redirects and crawl links on any host will be followed; scan only systems you are authorized to test.")
	}

	maxResponseBytes := cfg.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = 5 * 1024 * 1024
	}
	// Shared policy session: global budget (MaxRequestsTotal) is strictly shared across all targets
	sharedPolicy := plugin.NewPolicySession(plugin.PolicyConfig{
		MaxRequestsPerTarget: cfg.MaxRequestsPerTarget,
		MaxRequestsTotal:     cfg.MaxRequestsTotal,
		Scope:                cfg.Scope,
		RatePerSecond:        cfg.RatePerSecond,
		MaxResponseBytes:     maxResponseBytes,
		ProxyURL:             parsedProxy,
	}, nil)

	eng := engine.New(reg, cfg)
	for id, rec := range records {
		platform := rec.Platform
		if strings.TrimSpace(platform) == "" {
			platform = loader.AnyPlatform
		}
		eng.SetTrustRecord(id, rec.SHA256, platform)
	}
	eng.SetSharedPolicy(sharedPolicy)

	summary := BulkSummary{
		ScanTime:     time.Now().UTC().Format(time.RFC3339),
		TotalTargets: len(targets),
		Targets:      make([]BulkTargetSummary, 0, len(targets)),
	}

	var failOnTriggered bool
	totalCount := len(targets)

	for i, rawTarget := range targets {
		baseName := targetReportBaseName(rawTarget)
		targetSum := BulkTargetSummary{
			Target:  rawTarget,
			Reports: make(map[string]string),
		}

		// Check if global request budget is already exhausted
		if cfg.MaxRequestsTotal > 0 && sharedPolicy.TotalCount() >= cfg.MaxRequestsTotal {
			targetSum.Status = "budget_exhausted"
			targetSum.Error = "global request budget exhausted"
			summary.BudgetExhausted = true
			summary.Skipped++
			summary.Targets = append(summary.Targets, targetSum)
			fmt.Fprintf(cmd.ErrOrStderr(), "warn: [%d/%d] %s skipped (global request budget %d exhausted)\n", i+1, totalCount, rawTarget, cfg.MaxRequestsTotal)
			continue
		}

		// Check resume flag: skip targets that already have reports in outputDir
		if resume && isTargetAlreadyScanned(outputDir, baseName, formats) {
			targetSum.Status = "skipped_resume"
			summary.Skipped++
			for _, f := range formats {
				p := filepath.Join(outputDir, baseName+"."+f)
				if st, err := os.Stat(p); err == nil && st.Size() > 0 {
					targetSum.Reports[f] = p
				}
			}
			summary.Targets = append(summary.Targets, targetSum)
			fmt.Fprintf(cmd.OutOrStdout(), "[%d/%d] %s (skipped, resume)\n", i+1, totalCount, rawTarget)
			continue
		}

		normalized, err := validateScanTarget(rawTarget)
		if err != nil {
			targetSum.Status = "failed"
			targetSum.Error = err.Error()
			summary.Failed++
			summary.Targets = append(summary.Targets, targetSum)
			fmt.Fprintf(cmd.ErrOrStderr(), "error: [%d/%d] %s geçersiz: %v\n", i+1, totalCount, rawTarget, err)
			continue
		}

		if len(cfg.Scope) > 0 {
			if err := enforceScanScope(ctx, normalized, cfg.Scope); err != nil {
				targetSum.Status = "failed"
				targetSum.Error = err.Error()
				summary.Failed++
				summary.Targets = append(summary.Targets, targetSum)
				fmt.Fprintf(cmd.ErrOrStderr(), "error: [%d/%d] %s kapsam dışı: %v\n", i+1, totalCount, normalized, err)
				continue
			}
		}

		startReqs := sharedPolicy.TotalCount()
		fmt.Fprintf(cmd.OutOrStdout(), "[%d/%d] scanning %s...\n", i+1, totalCount, normalized)
		rep, err := eng.Run(ctx, normalized)
		endReqs := sharedPolicy.TotalCount()
		targetSum.Requests = endReqs - startReqs

		if err != nil {
			targetSum.Status = "failed"
			targetSum.Error = err.Error()
			summary.Failed++
			summary.Targets = append(summary.Targets, targetSum)
			fmt.Fprintf(cmd.ErrOrStderr(), "error: [%d/%d] tarama başarısız %s: %v\n", i+1, totalCount, normalized, err)
			continue
		}

		targetSum.Status = "completed"
		targetSum.FindingsCount = len(rep.Findings)
		for _, f := range rep.Findings {
			switch f.Severity {
			case plugin.SeverityHigh, plugin.SeverityCritical:
				targetSum.HighCount++
			case plugin.SeverityMedium:
				targetSum.MediumCount++
			case plugin.SeverityLow:
				targetSum.LowCount++
			default:
				targetSum.InfoCount++
			}
		}

		opts := reporter.Options{ShowTentative: showTentative, Target: normalized}
		for _, fmtName := range formats {
			outPath := filepath.Join(outputDir, baseName+"."+fmtName)
			f, err := openScanOutput(outPath)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "error: rapor dosyası açılamadı %s: %v\n", outPath, err)
				continue
			}
			writeErr := writeOneScanFormat(f, rep, fmtName, opts)
			_ = f.Close()
			if writeErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "error: format %s yazılamadı (%s): %v\n", fmtName, outPath, writeErr)
				continue
			}
			targetSum.Reports[fmtName] = outPath
		}

		if failLevel != "" && scanFailTriggered(rep, failLevel) {
			failOnTriggered = true
		}

		summary.Completed++
		summary.Targets = append(summary.Targets, targetSum)
		fmt.Fprintf(cmd.OutOrStdout(), "[%d/%d] completed %s: %d findings (%d reqs)\n",
			i+1, totalCount, normalized, len(rep.Findings), targetSum.Requests)
	}

	summary.TotalRequests = sharedPolicy.TotalCount()
	if cfg.MaxRequestsTotal > 0 && sharedPolicy.TotalCount() >= cfg.MaxRequestsTotal {
		summary.BudgetExhausted = true
	}

	summaryPath := filepath.Join(outputDir, "bulk_summary.json")
	summaryData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("bulk summary json marshal: %w", err)
	}
	if err := os.WriteFile(summaryPath, summaryData, 0o644); err != nil {
		return fmt.Errorf("bulk summary yazma hatası %q: %w", summaryPath, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nBulk scan complete: %d targets (%d completed, %d skipped, %d failed, %d total requests)\nSummary: %s\n",
		summary.TotalTargets, summary.Completed, summary.Skipped, summary.Failed, summary.TotalRequests, summaryPath)

	if failOnTriggered {
		return fmt.Errorf("scan: --fail-on %s triggered", failLevel)
	}
	return nil
}
