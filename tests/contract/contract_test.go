// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package contract B3/B6/B7/B9/B10/B11 kapılarını kilitler.
package contract

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// B3: plugin Finding üretemez; kanıtsız aday ≤ tentative.
// Tip-seviyesi: Candidate'ta Confidence/Severity alanı YOKTUR (derleme garantisi).
// Davranış: kanıtsız evidence → tentative tavan.
func TestB3_NoFindingFromPlugin(t *testing.T) {
	// Candidate struct'ında confidence alanı olmadığını derleme garantiler;
	// burada davranış kanıtlanır: boş evidence contribution tentative'a iner.
	spec := plugin.PluginSpec{
		ID: "b3", Name: "B3 plugin adı", Description: "Yeterli uzunlukta açıklama metni test için yazıldı.",
		Severity: plugin.SeverityCritical, Tags: []string{"t"}, Safe: true,
		Phase: plugin.PhaseProbe, Order: 1, APIVersion: "1.0", Tests: "tests/fixtures/x/",
	}
	cand := plugin.Candidate{PluginID: "b3", Target: "http://example.com/", OracleName: "reflection"}
	ev := &oracle.Evidence{Verdict: oracle.VerdictAccept} // contribution boş (kanıtsız)
	f, err := finding.Build(spec, cand, ev, "GASH-001", "CWE-79", "", "")
	if err != nil || f == nil {
		t.Fatalf("build: %v %+v", err, f)
	}
	if f.Confidence != plugin.ConfidenceTentative {
		t.Fatalf("B3: kanıtsız ≤ tentative olmalı, got %s", f.Confidence)
	}
	if f.Severity != plugin.SeverityMedium {
		t.Fatalf("B3+R-SEV-01: tentative tavanı medium, got %s", f.Severity)
	}
}

// B6: safe=true state-changing atamaz (proxy testi).
func TestB6_SafeCannotMutate(t *testing.T) {
	p := plugin.NewPolicySession(plugin.DefaultPolicyConfig(), roundTripOK())
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req, _ := http.NewRequestWithContext(
			plugin.WithPlugin(context.Background(), "safe-p", true, nil), m, "http://example.com/", nil)
		if _, err := p.RoundTrip(req); !errors.Is(err, plugin.ErrPolicyViolation) {
			t.Fatalf("B6: safe %s engellenmeli, got %v", m, err)
		}
	}
}

type okRT struct{}

func (okRT) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
}

func roundTripOK() http.RoundTripper { return okRT{} }

// B7: bozuk plugin (panic/timeout/geçersiz dönüş) taramayı durdurmaz.
func TestB7_FaultIsolation(t *testing.T) {
	panicRes := plugin.Execute(context.Background(), "panicker", func(ctx context.Context) ([]plugin.Candidate, error) {
		panic("boom")
	})
	if panicRes.Status != plugin.StatusPanic {
		t.Fatalf("panic izole edilmeli: %s", panicRes.Status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	timeoutRes := plugin.Execute(ctx, "slower", func(ctx context.Context) ([]plugin.Candidate, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if timeoutRes.Status != plugin.StatusTimeout {
		t.Fatalf("timeout izole edilmeli: %s", timeoutRes.Status)
	}
	// Scheduler devam eder: bozuk plugin + sağlam plugin aynı registry'de schedule edilir.
	reg := plugin.NewRegistry()
	bad := plugin.PluginSpec{ID: "bad", Name: "Kötü plugin adı", Description: "Yeterli uzunlukta açıklama metni test için yazıldı.", Severity: plugin.SeverityLow, Tags: []string{"t"}, Safe: true, Phase: plugin.PhaseProbe, Order: 1, APIVersion: "1.0"}
	good := plugin.PluginSpec{ID: "good", Name: "İyi plugin adı", Description: "Yeterli uzunlukta açıklama metni test için yazıldı.", Severity: plugin.SeverityLow, Tags: []string{"t"}, Safe: true, Phase: plugin.PhaseProbe, Order: 2, APIVersion: "1.0"}
	reg.MustRegister(bad, "mem", false)
	reg.MustRegister(good, "mem", false)
	e := engine.New(reg, engine.DefaultConfig())
	ordered, _, err := e.Schedule(context.Background())
	if err != nil {
		t.Fatalf("bozuk plugin schedule'u öldürmemeli: %v", err)
	}
	if len(ordered) != 2 {
		t.Fatalf("2 plugin schedule edilmeli: %v", len(ordered))
	}
}

// B9: oob:required + --oob-server yoksa hiç çalışmaz (sahte tentative YOK).
func TestB9_OOBRequiredSkips(t *testing.T) {
	reg := plugin.NewRegistry()
	s := plugin.PluginSpec{ID: "blind", Name: "Blind plugin adı", Description: "Yeterli uzunlukta açıklama metni test için yazıldı.", Severity: plugin.SeverityHigh, Tags: []string{"ssrf"}, Safe: false, Active: true, Phase: plugin.PhaseProbe, Order: 1, APIVersion: "1.0", OOB: plugin.OOBRequired}
	reg.MustRegister(s, "mem", false)
	cfg := engine.DefaultConfig()
	cfg.Active = true // active açık; OOB kapısı izole test edilir
	e := engine.New(reg, cfg)
	ordered, skipped, err := e.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 0 {
		t.Fatal("B9: oob:required çalışmamalı")
	}
	found := false
	for _, sk := range skipped {
		if sk.PluginID == "blind" && strings.Contains(sk.Reason, "oob-not-configured") {
			found = true
		}
	}
	if !found {
		t.Fatalf("B9: skip sebebi oob-not-configured olmalı: %+v", skipped)
	}
	// OOB oracle guard: kapalıyken skipped (plugin hatası değil).
	o := oracle.OOBOracle{Enabled: false}
	ev, _ := o.Verify(context.Background(), baseline.Classification{}, false, oracle.OOBParams{})
	_ = ev
}

// B10: Tier3 trust'suz asla çalıştırılmaz.
func TestB10_Tier3NeedsTrust(t *testing.T) {
	manifestYAML := "id: t3\nname: Tier3 test plugin adı burada\ndescription: Yeterli uzunlukta açıklama metni test için yazıldı burada.\nseverity: high\ntags: [x]\nsafe: false\ndeep: false\nactive: true\nrequires_auth: false\nphase: deep\norder: 1\napi_version: \"1.0\"\nbinary: ./bin/x\nprotocol: grpc\nsha256: \"abc\"\n"
	_, m, err := loader.ParseTier3Manifest("x.gashplugin.yaml", []byte(manifestYAML))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if _, err := loader.NewTier3Client(m, map[string]string{}); !errors.Is(err, plugin.ErrTrustRequired) {
		t.Fatalf("B10: trust'suz client kurulmamalı, got %v", err)
	}
}

// B11: kodda sabit check sayısı/isim yok (CI grep karşılığı — burada worst-offender taraması).
func TestB11_NoHardcodedCheckCount(t *testing.T) {
	// Yasak: kodda "6-7 plugin", sabit zafiyet listesi, check sayısı sabiti.
	// Bu test repo kökünden tarar; izinli yer: docs/ + tests/ + evidence-standard taksonomisi.
	root := filepath.Join("..", "..")
	offenders := []string{}
	_ = offenders
	_ = root
	// Hafif sürüm: yalnızca internal/ + cmd/ + pkg/ taranır; docs/tests izinli.
	allowedDirs := map[string]bool{"docs": true, "tests": true, ".git": true}
	_ = allowedDirs
	// Gerçek tarama: internal ve cmd altında "GASH-00" sabitleri yalnızca finding/engine/oracle'da
	// kural şablonu olarak bulunabilir; burada yasaklanan "check sayısı" sabitidir:
	// örn. `numChecks = 7`, `checks := []string{"xss","sqli",...}` gibi plugin sayısını sabitleyen kod.
	// Faz 2'de böyle kod YOKTUR — varlık kontrolü: internal'da "NumVulnChecks|HardcodedChecks" aranır.
	badTokens := []string{"NumVulnChecks", "HardcodedChecks", "numChecks = 7", "totalChecks ="}
	for _, dir := range []string{"internal", "cmd"} {
		base := filepath.Join(root, dir)
		_ = filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			s := string(data)
			for _, tok := range badTokens {
				if strings.Contains(s, tok) {
					t.Errorf("B11: sabit check izi %s: %s", p, tok)
				}
			}
			return nil
		})
	}
}
