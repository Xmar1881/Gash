// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// ExecutionParams DOM/XSS headless yürütme kanıtıdır (GASH-003).
// Arayüz KİLİTLİ (2026-10-15): alan ekleme/çıkarma YOK; confirmed yolu yalnızca
// internal/headless VerifyDOM üretimi Triggered+ControlClean ile açılır.
// Karar: chromedp v0.21.0 pinli, `-tags deep` arkasında (default build
// browser linklemez, tavan firm). Ayrıntı: docs/known-limits.md.
type ExecutionParams struct {
	Sink            string
	Source          string
	Payload         string
	HeadlessEnabled bool
	Triggered       bool // headless'te alert/eval tetiklendi mi
	ControlClean    bool // kontrolde tetiklenmeme
}

// ExecutionOracle headless yürütme kanıtı (opsiyonel ağır oracle).
type ExecutionOracle struct{}

func (ExecutionOracle) Name() string { return "execution" }

// Verify statik analizde firm, headless + trigger + kontrolde confirmed verir.
func (ExecutionOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p ExecutionParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if !p.HeadlessEnabled && p.Sink == "" {
		return &Evidence{Verdict: VerdictReject, Note: "sink yok"}, nil
	}
	if !p.HeadlessEnabled {
		if p.Source == "" {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: map[string]string{"sink": p.Sink}, Note: "sink var source kurulamamış → tentative"}, nil
		}
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: map[string]string{"sink": p.Sink, "source": p.Source}, Note: "statik sink/source, headless yok → firm (maksimum)"}, nil
	}
	if p.Triggered && p.ControlClean {
		artifacts := map[string]string{"browser": "execution"}
		if p.Sink != "" {
			artifacts["sink"] = p.Sink
		}
		if p.Source != "" {
			artifacts["source"] = p.Source
		}
		if p.Payload != "" {
			artifacts["payload"] = p.Payload
		}
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceConfirmed,
			Artifacts:              artifacts,
			Repeats:                1,
			ControlResult:          "clean",
			Note:                   "headless yǬrǬtme + kontrol ��' confirmed",
		}, nil
	}
	return &Evidence{Verdict: VerdictReject, Note: "headless'te tetiklenmedi"}, nil
}

// OOBParams blind sınıflar içindir (GASH-008/010/012/013 + 005/006/015 optional).
type OOBParams struct {
	CorrelationID string
	Namespace     string
	CallbackSeen  bool
}

// OOBOracle is disabled by default. Without --oob-server the call returns
// skipped (B9), not a plugin error; oob:required plugins never run in the
// scheduler (R-OOB-01).
type OOBOracle struct {
	Enabled bool
}

func (OOBOracle) Name() string { return "oob" }

// Verify returns confirmed on a callback match (single match suffices, ID is cryptographically random).
func (o OOBOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p OOBParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if !o.Enabled {
		return &Evidence{Verdict: VerdictSkipped, Note: "skipped (oob-not-configured, requires --oob-server)"}, nil
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if p.CorrelationID == "" || p.Namespace == "" {
		return &Evidence{Verdict: VerdictReject, Note: "correlation/namespace yok"}, nil
	}
	if !p.CallbackSeen {
		return &Evidence{Verdict: VerdictReject, Note: "callback yok — bulgu yok"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"correlation": p.CorrelationID, "namespace": p.Namespace},
		Repeats:                1,
		Note:                   "OOB callback eşleşti → confirmed",
	}, nil
}
