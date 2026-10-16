// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

func TestReadTargetFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")

	content := `
# Comment line
http://example.com/api
   
   # Another comment
http://sub.example.com:8080/v2 # Inline comment
https://127.0.0.1:9000/
`
	if err := os.WriteFile(targetFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	targets, err := readTargetFile(targetFile)
	if err != nil {
		t.Fatalf("readTargetFile failed: %v", err)
	}

	expected := []string{
		"http://example.com/api",
		"http://sub.example.com:8080/v2",
		"https://127.0.0.1:9000/",
	}

	if len(targets) != len(expected) {
		t.Fatalf("expected %d targets, got %d: %v", len(expected), len(targets), targets)
	}
	for i, exp := range expected {
		if targets[i] != exp {
			t.Errorf("target[%d] = %q, expected %q", i, targets[i], exp)
		}
	}

	// Test non-existent file
	if _, err := readTargetFile(filepath.Join(tmpDir, "non_existent.txt")); err == nil {
		t.Errorf("expected error for non-existent file")
	}

	// Test empty file
	emptyFile := filepath.Join(tmpDir, "empty.txt")
	_ = os.WriteFile(emptyFile, []byte("# only comments\n   \n"), 0o644)
	if _, err := readTargetFile(emptyFile); err == nil {
		t.Errorf("expected error for empty target file")
	}
}

func TestTargetReportBaseName(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"http://example.com", "example.com"},
		{"http://example.com/", "example.com"},
		{"http://example.com:8080", "example.com_8080"},
		{"http://example.com:8080/api/v1", "example.com_8080_api_v1"},
		{"https://sub.domain.org/path/test/", "sub.domain.org_path_test"},
		{"http://127.0.0.1:8000/app", "127.0.0.1_8000_app"},
	}

	for _, tc := range cases {
		got := targetReportBaseName(tc.input)
		if got != tc.expected {
			t.Errorf("targetReportBaseName(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestIsTargetAlreadyScanned(t *testing.T) {
	tmpDir := t.TempDir()
	baseName := "test_target"

	// Before file exists
	if isTargetAlreadyScanned(tmpDir, baseName, []string{"json", "sarif"}) {
		t.Errorf("expected false before file creation")
	}

	// Create empty file (0 bytes) -> should still be false
	jsonPath := filepath.Join(tmpDir, baseName+".json")
	_ = os.WriteFile(jsonPath, []byte(""), 0o644)
	if isTargetAlreadyScanned(tmpDir, baseName, []string{"json", "sarif"}) {
		t.Errorf("expected false for 0-byte file")
	}

	// Write content -> should be true
	_ = os.WriteFile(jsonPath, []byte(`{"findings":[]}`), 0o644)
	if !isTargetAlreadyScanned(tmpDir, baseName, []string{"json", "sarif"}) {
		t.Errorf("expected true for existing non-empty report")
	}
}

func TestRunBulkScanExecution(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Target 1</h1></body></html>`))
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Target 2</h1></body></html>`))
	}))
	defer srv2.Close()

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	targetsContent := fmt.Sprintf("%s\n# Comment\n%s\n", srv1.URL, srv2.URL)
	if err := os.WriteFile(targetFile, []byte(targetsContent), 0o644); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	outDir := filepath.Join(tmpDir, "bulk_reports")
	cmd := &cobra.Command{}
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	reg := plugin.NewRegistry()
	yamlPath := filepath.Join("..", "..", "plugins", "clickjacking", "clickjacking-frameable.yaml")
	spec, _, err := loader.LoadTier1File(yamlPath)
	if err != nil {
		t.Fatalf("failed to load test plugin: %v", err)
	}
	reg.MustRegister(*spec, yamlPath, false)

	cfg := engine.DefaultConfig()
	cfg.Safe = true
	cfg.MaxRequestsPerTarget = 50
	cfg.MaxRequestsTotal = 100
	cfg.MaxPages = 1
	cfg.Depth = 1

	records := make(map[string]loader.TrustRecord)
	formats := []string{"json", "sarif"}

	// 1. First run: should scan both targets and write reports + bulk_summary.json
	err = runBulkScan(context.Background(), cmd, reg, cfg, records, targetFile, outDir, false, formats, "", false)
	if err != nil {
		t.Fatalf("runBulkScan failed: %v", err)
	}

	// Verify reports exist for both targets
	base1 := targetReportBaseName(srv1.URL)
	base2 := targetReportBaseName(srv2.URL)

	for _, base := range []string{base1, base2} {
		jsonPath := filepath.Join(outDir, base+".json")
		sarifPath := filepath.Join(outDir, base+".sarif")
		if st, err := os.Stat(jsonPath); err != nil || st.Size() == 0 {
			t.Errorf("expected non-empty JSON report at %s", jsonPath)
		}
		if st, err := os.Stat(sarifPath); err != nil || st.Size() == 0 {
			t.Errorf("expected non-empty SARIF report at %s", sarifPath)
		}
	}

	// Verify bulk_summary.json
	summaryPath := filepath.Join(outDir, "bulk_summary.json")
	summaryData, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("failed to read bulk_summary.json: %v", err)
	}

	var summary BulkSummary
	if err := json.Unmarshal(summaryData, &summary); err != nil {
		t.Fatalf("failed to unmarshal bulk_summary.json: %v", err)
	}

	if summary.TotalTargets != 2 {
		t.Errorf("expected 2 total targets, got %d", summary.TotalTargets)
	}
	if summary.Completed != 2 {
		t.Errorf("expected 2 completed targets, got %d", summary.Completed)
	}
	if summary.Skipped != 0 {
		t.Errorf("expected 0 skipped targets, got %d", summary.Skipped)
	}
	if summary.TotalRequests <= 0 {
		t.Errorf("expected total requests > 0, got %d", summary.TotalRequests)
	}

	// 2. Resume test: run with resume=true -> both should be skipped!
	err = runBulkScan(context.Background(), cmd, reg, cfg, records, targetFile, outDir, true, formats, "", false)
	if err != nil {
		t.Fatalf("runBulkScan with resume failed: %v", err)
	}

	summaryData, err = os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("failed to read bulk_summary.json: %v", err)
	}
	var resumeSummary BulkSummary
	if err := json.Unmarshal(summaryData, &resumeSummary); err != nil {
		t.Fatalf("failed to unmarshal bulk_summary.json: %v", err)
	}
	if resumeSummary.Skipped != 2 {
		t.Errorf("expected 2 skipped targets on resume, got %d", resumeSummary.Skipped)
	}
	if resumeSummary.Completed != 0 {
		t.Errorf("expected 0 completed targets on resume, got %d", resumeSummary.Completed)
	}
}

func TestRunBulkScanBudgetSharing(t *testing.T) {
	reqCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	// 5 targets
	content := fmt.Sprintf("%s/1\n%s/2\n%s/3\n%s/4\n%s/5\n", srv.URL, srv.URL, srv.URL, srv.URL, srv.URL)
	_ = os.WriteFile(targetFile, []byte(content), 0o644)

	outDir := filepath.Join(tmpDir, "budget_reports")
	cmd := &cobra.Command{}
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	reg := plugin.NewRegistry()
	yamlPath := filepath.Join("..", "..", "plugins", "clickjacking", "clickjacking-frameable.yaml")
	spec, _, err := loader.LoadTier1File(yamlPath)
	if err != nil {
		t.Fatalf("failed to load test plugin: %v", err)
	}
	reg.MustRegister(*spec, yamlPath, false)

	cfg := engine.DefaultConfig()
	cfg.Safe = true
	// Strict global budget: only 2 total requests allowed across all targets
	cfg.MaxRequestsTotal = 2
	cfg.MaxRequestsPerTarget = 10
	cfg.MaxPages = 1
	cfg.Depth = 1

	records := make(map[string]loader.TrustRecord)
	formats := []string{"json"}

	err = runBulkScan(context.Background(), cmd, reg, cfg, records, targetFile, outDir, false, formats, "", false)
	if err != nil {
		t.Fatalf("runBulkScan failed: %v", err)
	}

	summaryPath := filepath.Join(outDir, "bulk_summary.json")
	summaryData, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("failed to read bulk_summary.json: %v", err)
	}
	var summary BulkSummary
	if err := json.Unmarshal(summaryData, &summary); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !summary.BudgetExhausted {
		t.Errorf("expected BudgetExhausted to be true")
	}
	// Total requests must be capped at MaxRequestsTotal
	if summary.TotalRequests > 2 {
		t.Errorf("expected total requests <= 2, got %d", summary.TotalRequests)
	}
	// At least some targets must be marked budget_exhausted
	foundBudgetExhausted := false
	for _, tgt := range summary.Targets {
		if tgt.Status == "budget_exhausted" {
			foundBudgetExhausted = true
			break
		}
	}
	if !foundBudgetExhausted {
		t.Errorf("expected at least one target to have status 'budget_exhausted'")
	}
}

func TestScanCLIFlagValidation(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "targets.txt")
	_ = os.WriteFile(targetFile, []byte("http://example.com\n"), 0o644)

	// Neither target nor target-file
	cmd1 := newScanCmd()
	cmd1.SetArgs([]string{})
	if err := cmd1.Execute(); err == nil || !strings.Contains(err.Error(), "--target veya --target-file zorunlu") {
		t.Errorf("expected missing target error, got %v", err)
	}

	// Both target and target-file
	cmd2 := newScanCmd()
	cmd2.SetArgs([]string{"--target", "http://example.com", "--target-file", targetFile})
	if err := cmd2.Execute(); err == nil || !strings.Contains(err.Error(), "birlikte kullanılamaz") {
		t.Errorf("expected mutually exclusive error, got %v", err)
	}

	// target-file with --output (should reject and advise --output-dir)
	cmd3 := newScanCmd()
	cmd3.SetArgs([]string{"--target-file", targetFile, "--output", "out.json"})
	if err := cmd3.Execute(); err == nil || !strings.Contains(err.Error(), "--output yerine --output-dir") {
		t.Errorf("expected --output-dir recommendation error, got %v", err)
	}
}

func TestScanCLISingleTargetPreserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "single_report.json")

	cmd := newScanCmd()
	cmd.SetArgs([]string{
		"--target", srv.URL,
		"--format", "json",
		"--output", outFile,
		"--max-pages", "1",
		"--depth", "1",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("single target scan failed: %v", err)
	}

	if st, err := os.Stat(outFile); err != nil || st.Size() == 0 {
		t.Errorf("expected single target JSON report to be written at %s", outFile)
	}
}

func TestScanCLIProxyFlag(t *testing.T) {
	// Invalid proxy scheme/format
	cmdInvalid := newScanCmd()
	cmdInvalid.SetArgs([]string{
		"--target", "http://example.com",
		"--proxy", "not-a-valid-proxy-url",
	})
	if err := cmdInvalid.Execute(); err == nil || !strings.Contains(err.Error(), "--proxy geçersiz") {
		t.Errorf("expected invalid proxy error, got %v", err)
	}

	// Valid proxy routing
	var proxyHits int
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>proxied</body></html>`))
	}))
	defer proxySrv.Close()

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>direct</body></html>`))
	}))
	defer targetSrv.Close()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "proxy_report.json")

	cmdValid := newScanCmd()
	cmdValid.SetArgs([]string{
		"--target", targetSrv.URL,
		"--proxy", proxySrv.URL,
		"--format", "json",
		"--output", outFile,
		"--max-pages", "1",
		"--depth", "1",
	})
	if err := cmdValid.Execute(); err != nil {
		t.Fatalf("scan with --proxy failed: %v", err)
	}

	if proxyHits == 0 {
		t.Errorf("expected requests to pass through proxy, got %d hits", proxyHits)
	}
}
