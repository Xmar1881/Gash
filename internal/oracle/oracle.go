// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package oracle engine-owned kanıt kütüphanesidir (A-06).
// Ortak ön adımlar (baseline Untrusted → reject, taint → reject) atlanamaz.
// Params tipli struct'tır; map[string]any sessizliği YOKTUR.
package oracle

import (
	"context"
	"fmt"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// Verdict kanıt hükmüdür.
type Verdict string

const (
	VerdictAccept       Verdict = "accept"
	VerdictReject       Verdict = "reject"
	VerdictInconclusive Verdict = "inconclusive"
	VerdictSkipped      Verdict = "skipped"
)

// Evidence oracle çıktısıdır.
type Evidence struct {
	Verdict                Verdict
	ConfidenceContribution plugin.Confidence
	Artifacts              map[string]string
	Repeats                int
	ControlResult          string
	Note                   string
}

// Oracle tek sözleşmedir: Verify(ctx, ...) → (Evidence, error).
// Her oracle tipli params alır; generic registry Name() ile listelenir.
type Oracle interface {
	Name() string
}

// guard ortak ön adımdır: Untrusted/taint → reject (atlamasız).
// WAF engeli burada bulguya değil çözüme bağlanır: blok sayfa reddedilir,
// ancak probe agresif modda bypass varyantıyla temiz yanıt alırsa o yanıt
// normal doğrulanır (internal/wafbypass + probe.EnableWAFBypass). Sessiz
// düşürme YOKTUR — WAF varlığı Report.Stats'ta (waf_detected) taşınır.
func guard(cls baseline.Classification, tainted bool) *Evidence {
	if cls.Untrusted {
		return &Evidence{Verdict: VerdictReject, Note: "baseline untrusted (WAF/blok) — kanıt olamaz"}
	}
	if tainted {
		return &Evidence{Verdict: VerdictReject, Note: "tainted response — başka plugin izi kanıt olamaz"}
	}
	return nil
}

// CheckContext iptal/timeout taşır (tüm Verify'lar ilk satırda çağırır).
func checkCtx(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("oracle ctx: %w", ctx.Err())
	default:
		return nil
	}
}
