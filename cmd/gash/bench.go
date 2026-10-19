// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/bench"
	"github.com/spf13/cobra"
)

func newBenchCmd() *cobra.Command {
	benchCmd := &cobra.Command{
		Use:   "bench",
		Short: "Automated scanner benchmark (ground truth, Gash/Nuclei, reports)",
		Long: "Benchmark harness with independently verified ground truth.\n" +
			"Refuses non-lab targets by default; docker is only needed for the compose lab.",
	}
	benchCmd.AddCommand(newBenchRunCmd(), newBenchValidateCmd(), newBenchCompareCmd(), newBenchBaselineCmd(), newBenchLabCmd())
	return benchCmd
}

func newBenchBaselineCmd() *cobra.Command {
	var (
		reportPath string
		tool       string
		outPath    string
	)
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Extract a compact baseline file from a benchmark report",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(reportPath)
			if err != nil {
				return fmt.Errorf("bench baseline: read %s: %w", reportPath, err)
			}
			var rep bench.Report
			if err := json.Unmarshal(raw, &rep); err != nil {
				return fmt.Errorf("bench baseline: parse %s: %w", reportPath, err)
			}
			b, err := bench.BaselineFromReport(&rep, tool)
			if err != nil {
				return err
			}
			encoded, err := json.MarshalIndent(b, "", "  ")
			if err != nil {
				return err
			}
			if outPath == "" {
				fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return nil
			}
			if err := os.WriteFile(outPath, append(encoded, '\n'), 0o644); err != nil {
				return fmt.Errorf("bench baseline: write %s: %w", outPath, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "baseline written: %s (tool=%s dataset=%s TP=%d FP=%d)\n",
				outPath, b.Tool, b.Dataset, b.Score.TP, b.Score.FP)
			return nil
		},
	}
	cmd.Flags().StringVar(&reportPath, "report", "", "benchmark report.json (required)")
	cmd.Flags().StringVar(&tool, "tool", "gash", "tool section to extract")
	cmd.Flags().StringVar(&outPath, "out", "", "output baseline file (default: stdout)")
	_ = cmd.MarkFlagRequired("report")
	return cmd
}

func newBenchRunCmd() *cobra.Command {
	var (
		dataset            string
		outDir             string
		repoDir            string
		gashBin            string
		nucleiBin          string
		tools              []string
		allowNonLab        bool
		noBrowserVerify    bool
		baseline           string
		minPrecision       float64
		maxRecallDrop      float64
		maxRequestIncrease float64
		maxDurationInc     float64
		failOnRegression   bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the benchmark and write the report directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, err := resolveRepoDir(repoDir)
			if err != nil {
				return err
			}
			runner := bench.NewRunner(bench.RunOptions{
				DatasetPath:     dataset,
				OutDir:          outDir,
				RepoDir:         repo,
				GashBin:         gashBin,
				NucleiBin:       nucleiBin,
				Tools:           tools,
				AllowNonLab:     allowNonLab,
				NoBrowserVerify: noBrowserVerify,
				BaselinePath:    baseline,
				Gate: bench.GateThresholds{
					MinPrecision:        minPrecision,
					MaxRecallDrop:       maxRecallDrop,
					MaxRequestIncrease:  maxRequestIncrease,
					MaxDurationIncrease: maxDurationInc,
				},
				Logf: func(format string, args ...any) {
					fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", args...)
				},
			})
			rep, err := runner.Run(cmd.Context())
			if err != nil {
				return err
			}
			printBenchSummary(cmd, rep)
			if rep.Gate != nil && !rep.Gate.Passed {
				if failOnRegression {
					return fmt.Errorf("bench: regression gate failed: %s", strings.Join(rep.Gate.Reasons, "; "))
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "bench: WARNING: regression gate failed (pass --fail-on-regression to enforce)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dataset, "dataset", "", "dataset YAML (required), e.g. bench/datasets/fixtures.yaml")
	cmd.Flags().StringVar(&outDir, "out", "", "report output directory (default bench/results/<timestamp>)")
	cmd.Flags().StringVar(&repoDir, "repo", "", "repository root used as scan working directory (default: current dir)")
	cmd.Flags().StringVar(&gashBin, "gash-bin", "auto", "gash binary to benchmark (auto = this executable)")
	cmd.Flags().StringVar(&nucleiBin, "nuclei-bin", "", "nuclei binary (default: PATH lookup)")
	cmd.Flags().StringSliceVar(&tools, "tool", []string{"gash", "nuclei"}, "tools to run: gash,nuclei")
	cmd.Flags().BoolVar(&allowNonLab, "allow-non-lab", false, "allow datasets with non-loopback targets (unsafe; explicit opt-in)")
	cmd.Flags().BoolVar(&noBrowserVerify, "no-browser-verify", false, "skip browser-execution verification (DOM XSS scenarios stay unverified)")
	cmd.Flags().StringVar(&baseline, "baseline", "", "baseline file for the regression gate (report.json or baseline.json)")
	cmd.Flags().Float64Var(&minPrecision, "min-precision", 0.99, "gate: minimum precision")
	cmd.Flags().Float64Var(&maxRecallDrop, "max-recall-drop", 0, "gate: allowed recall drop (0 = none)")
	cmd.Flags().Float64Var(&maxRequestIncrease, "max-request-increase", 0.25, "gate: allowed relative HTTP request increase")
	cmd.Flags().Float64Var(&maxDurationInc, "max-duration-increase", 0.5, "gate: allowed relative duration increase")
	cmd.Flags().BoolVar(&failOnRegression, "fail-on-regression", false, "exit non-zero when the regression gate fails")
	_ = cmd.MarkFlagRequired("dataset")
	return cmd
}

func newBenchValidateCmd() *cobra.Command {
	var allowNonLab bool
	cmd := &cobra.Command{
		Use:   "validate <dataset.yaml>",
		Short: "Validate a dataset (schema, ids, lab-only guard) without scanning",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ds, err := bench.LoadDataset(args[0])
			if err != nil {
				return err
			}
			if err := bench.Validate(ds, allowNonLab); err != nil {
				return err
			}
			categories := map[string]int{}
			expected := map[string]int{}
			for _, sc := range ds.Scenarios {
				categories[sc.Category]++
				expected[sc.Expected]++
			}
			fmt.Fprintf(cmd.OutOrStdout(), "dataset valid: %s (%s)\n", ds.Name, ds.Kind)
			fmt.Fprintf(cmd.OutOrStdout(), "sha256: %s\n", ds.SHA256)
			fmt.Fprintf(cmd.OutOrStdout(), "targets: %d, scenarios: %d\n", len(ds.Targets), len(ds.Scenarios))
			for k, v := range categories {
				fmt.Fprintf(cmd.OutOrStdout(), "  category %-24s %d\n", k, v)
			}
			for k, v := range expected {
				fmt.Fprintf(cmd.OutOrStdout(), "  expected %-24s %d\n", k, v)
			}
			nucleiTags := len(ds.Nuclei.Tags)
			fmt.Fprintf(cmd.OutOrStdout(), "nuclei tags: %d, gash args: %d, unscored plugins: %d\n", nucleiTags, len(ds.Gash.Args), len(ds.UnscoredPlugins))
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowNonLab, "allow-non-lab", false, "allow non-loopback targets")
	return cmd
}

func newBenchCompareCmd() *cobra.Command {
	var (
		baselinePath       string
		currentPath        string
		minPrecision       float64
		maxRecallDrop      float64
		maxRequestIncrease float64
		maxDurationInc     float64
	)
	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Compare a report against a baseline (regression gate)",
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := bench.LoadBaseline(baselinePath)
			if err != nil {
				return err
			}
			cur, err := bench.LoadBaseline(currentPath)
			if err != nil {
				return err
			}
			gate := bench.CompareBaseline(base, cur, bench.GateThresholds{
				MinPrecision:        minPrecision,
				MaxRecallDrop:       maxRecallDrop,
				MaxRequestIncrease:  maxRequestIncrease,
				MaxDurationIncrease: maxDurationInc,
			})
			fmt.Fprintf(cmd.OutOrStdout(), "baseline: %s (%s)\n", base.GeneratedAt, base.Dataset)
			fmt.Fprintf(cmd.OutOrStdout(), "current:  %s (%s)\n", cur.GeneratedAt, cur.Dataset)
			fmt.Fprintf(cmd.OutOrStdout(), "precision: %s -> %s | recall: %s -> %s\n",
				fmtPtr(base.Score.Precision), fmtPtr(cur.Score.Precision), fmtPtr(base.Score.Recall), fmtPtr(cur.Score.Recall))
			for _, d := range gate.Deltas {
				fmt.Fprintf(cmd.OutOrStdout(), "delta %-12s %s -> %s\n", d.Metric, d.Before, d.After)
			}
			for _, reason := range gate.Reasons {
				fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", reason)
			}
			if !gate.Passed {
				return fmt.Errorf("bench compare: regression detected")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "baseline report/baseline file (required)")
	cmd.Flags().StringVar(&currentPath, "current", "", "current report file (required)")
	cmd.Flags().Float64Var(&minPrecision, "min-precision", 0.99, "minimum precision")
	cmd.Flags().Float64Var(&maxRecallDrop, "max-recall-drop", 0, "allowed recall drop")
	cmd.Flags().Float64Var(&maxRequestIncrease, "max-request-increase", 0.25, "allowed relative request increase")
	cmd.Flags().Float64Var(&maxDurationInc, "max-duration-increase", 0.5, "allowed relative duration increase")
	_ = cmd.MarkFlagRequired("baseline")
	_ = cmd.MarkFlagRequired("current")
	return cmd
}

func newBenchLabCmd() *cobra.Command {
	var composeFile string
	lab := &cobra.Command{Use: "lab", Short: "Lab lifecycle (Docker Compose: DVWA/JuiceShop/WebGoat)"}
	up := &cobra.Command{
		Use:   "up",
		Short: "Start the compose lab (localhost-only, pinned images)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompose(cmd, composeFile, "up", "-d")
		},
	}
	down := &cobra.Command{
		Use:   "down",
		Short: "Stop the compose lab (keeps volumes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompose(cmd, composeFile, "down")
		},
	}
	reset := &cobra.Command{
		Use:   "reset",
		Short: "Stop the compose lab and wipe volumes (fresh state)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runCompose(cmd, composeFile, "down", "-v"); err != nil {
				return err
			}
			return runCompose(cmd, composeFile, "up", "-d")
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show compose lab status plus endpoint reachability",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runCompose(cmd, composeFile, "ps"); err != nil {
				return err
			}
			client := &http.Client{Timeout: 3 * time.Second}
			for _, ep := range []string{"http://127.0.0.1:8081/", "http://127.0.0.1:8082/", "http://127.0.0.1:8083/"} {
				resp, err := client.Get(ep)
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "%-24s unreachable (%v)\n", ep, err)
					continue
				}
				resp.Body.Close()
				fmt.Fprintf(cmd.OutOrStdout(), "%-24s HTTP %d\n", ep, resp.StatusCode)
			}
			return nil
		},
	}
	lab.AddCommand(up, down, reset, status)
	lab.PersistentFlags().StringVar(&composeFile, "file", "docker-compose.lab.yml", "compose file")
	return lab
}

func runCompose(cmd *cobra.Command, composeFile string, args ...string) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("bench lab: docker not found in PATH (BLOCKED on this machine): %w", err)
	}
	full := append([]string{"compose", "-f", composeFile}, args...)
	c := exec.CommandContext(cmd.Context(), "docker", full...)
	c.Stdout = cmd.OutOrStdout()
	c.Stderr = cmd.ErrOrStderr()
	if err := c.Run(); err != nil {
		return fmt.Errorf("bench lab: docker %s: %w", strings.Join(full, " "), err)
	}
	return nil
}

func resolveRepoDir(flag string) (string, error) {
	if flag != "" {
		return filepath.Abs(flag)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(wd, "plugins")); err == nil {
		return wd, nil
	}
	return wd, nil
}

func printBenchSummary(cmd *cobra.Command, rep *bench.Report) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "benchmark %s: dataset=%s scenarios=%d\n", rep.SchemaVersion, rep.Dataset.Name, rep.Dataset.ScenarioCount)
	for _, tool := range []string{"gash", "nuclei"} {
		res, ok := rep.Tools[tool]
		if !ok {
			continue
		}
		if !res.Available {
			fmt.Fprintf(out, "%-6s unavailable: %s\n", tool, res.Reason)
			continue
		}
		prec, rec, f1 := "N/A", "N/A", "N/A"
		if res.Score.Precision != nil {
			prec = fmt.Sprintf("%.3f", *res.Score.Precision)
		}
		if res.Score.Recall != nil {
			rec = fmt.Sprintf("%.3f", *res.Score.Recall)
		}
		if res.Score.F1 != nil {
			f1 = fmt.Sprintf("%.3f", *res.Score.F1)
		}
		fmt.Fprintf(out, "%-6s TP=%d FP=%d TN=%d FN=%d weak=%d precision=%s recall=%s F1=%s findings=%d duration=%s requests(reported=%s observed=%s)\n",
			tool, res.Score.TP, res.Score.FP, res.Score.TN, res.Score.FN, res.Score.Weak,
			prec, rec, f1, res.Findings, time.Duration(res.DurationMS)*time.Millisecond,
			fmtPtrInt(res.ReportedRequests), fmtPtrInt(res.ObservedRequests))
	}
	if len(rep.Missed) > 0 {
		fmt.Fprintf(out, "failed/missed scenarios: %d (see summary.md)\n", len(rep.Missed))
	}
	if len(rep.Unverified) > 0 {
		fmt.Fprintf(out, "unverified scenarios (excluded): %d\n", len(rep.Unverified))
	}
	if rep.Manifest.Environment["report_dir"] != "" {
		fmt.Fprintf(out, "report: %s\n", rep.Manifest.Environment["report_dir"])
	}
}

func fmtPtr(v *float64) string {
	if v == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.3f", *v)
}

func fmtPtrInt(v *int64) string {
	if v == nil {
		return "N/A"
	}
	return fmt.Sprintf("%d", *v)
}
