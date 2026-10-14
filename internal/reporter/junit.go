// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package reporter

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// WriteJUnit JUnit XML çıktısıdır (CI kapısı, P2.4).
// What: Her bulgu bir testcase; firm/confirmed → failure, tentative → skipped
// (yalnızca --show-tentative ile görünür); skipped plugin'ler de skipped case'dir.
// Why: Jenkins/GitLab/ADO JUnit'i doğrudan yutar; SARIF bilmeyen hatlar için CI sözleşmesi.
func WriteJUnit(w io.Writer, rep *engine.Report, opts Options) error {
	vis, _ := filter(rep, opts)

	type failure struct {
		Message string `xml:"message,attr"`
		Type    string `xml:"type,attr"`
		Text    string `xml:",chardata"`
	}
	type skipped struct {
		Message string `xml:"message,attr"`
	}
	type testcase struct {
		Classname string   `xml:"classname,attr"`
		Name      string   `xml:"name,attr"`
		Failure   *failure `xml:"failure,omitempty"`
		Skipped   *skipped `xml:"skipped,omitempty"`
	}
	type testsuite struct {
		XMLName   xml.Name   `xml:"testsuite"`
		Name      string     `xml:"name,attr"`
		Tests     int        `xml:"tests,attr"`
		Failures  int        `xml:"failures,attr"`
		Skipped   int        `xml:"skipped,attr"`
		Testcases []testcase `xml:"testcase"`
	}
	type suites struct {
		XMLName xml.Name    `xml:"testsuites"`
		Suites  []testsuite `xml:"testsuite"`
	}

	var cases []testcase
	failures := 0
	skippedN := 0
	for _, f := range vis {
		tc := testcase{
			Classname: "gash." + f.RuleID,
			Name:      fmt.Sprintf("[%s/%s] %s (%s)", f.Severity, f.Confidence, f.Title, f.Fingerprint),
		}
		switch f.Confidence {
		case string(plugin.ConfidenceConfirmed), string(plugin.ConfidenceFirm):
			tc.Failure = &failure{
				Message: fmt.Sprintf("%s %s %s", f.RuleID, f.Severity, f.Confidence),
				Type:    "vulnerability",
				Text:    fmt.Sprintf("%s target=%s plugin=%s fp=%s", f.Title, f.Target, f.PluginID, f.Fingerprint),
			}
			failures++
		default:
			tc.Skipped = &skipped{Message: "tentative: zayıf sinyal, --show-tentative ile incelenir"}
			skippedN++
		}
		cases = append(cases, tc)
	}
	for _, s := range rep.Skipped {
		cases = append(cases, testcase{
			Classname: "gash.skipped",
			Name:      "skipped " + s.PluginID,
			Skipped:   &skipped{Message: s.Reason},
		})
		skippedN++
	}
	if cases == nil {
		cases = []testcase{}
	}
	doc := suites{Suites: []testsuite{{
		Name:      "gash " + rep.Target,
		Tests:     len(cases),
		Failures:  failures,
		Skipped:   skippedN,
		Testcases: cases,
	}}}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return fmt.Errorf("reporter junit: %w", err)
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("reporter junit: %w", err)
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("reporter junit: %w", err)
	}
	return nil
}
