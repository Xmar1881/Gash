// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// VerbTamperParams baseline/varyant karşılaştırmasıdır (GASH-036, CWE-650).
// Baseline: korumalı yolun düz GET yanıtı (401/403 beklenir).
// Variant: metot/başlık değiştirilmiş isteğin yanıtı (2xx aranır).
// Tek-kanallı gözlem olduğundan tavan firm'dır; yıkıcı metot YOKTUR.
type VerbTamperParams struct {
	BaselineStatus int
	BaselineBody   string
	VariantStatus  int
	VariantBody    string
	VariantMethod  string // "head", "options", "x-http-method-override", ...
}

// VerbTamperOracle auth kısıtının metot/başlık düzeyinde atlanabildiğini arar.
// What: Baseline 401/403 + varyant 2xx + anlamlı gövde + maskeli ayrışma → firm.
// Why: Bazı sunucular GET'i korurken HEAD/OPTIONS veya X-HTTP-Method-Override/
// X-Original-URL/X-Rewrite-URL varyantlarını korumasız bırakır. Boş gövde
// (HEAD) veya baseline ile aynı maskeli gövde (yanlış statü) bypass sayılmaz.
type VerbTamperOracle struct{}

func (VerbTamperOracle) Name() string { return "verb-tamper" }

// verbTamperMinBody: altında gövde "gerçek içerik" sayılmaz (HEAD/OPTIONS
// boş veya protokol-şablonu yanıtları bypass kanıtı değildir). 24 bayt eşiği
// "Allow: GET, POST, OPTIONS" (~24) gibi standart yanıtları dışarıda tutar.
const verbTamperMinBody = 24

// Verify karar verir; guard/checkCtx ortak ön adımları atlanamaz.
func (VerbTamperOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p VerbTamperParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if p.BaselineStatus != 401 && p.BaselineStatus != 403 {
		return &Evidence{Verdict: VerdictReject, Note: "baseline 401/403 değil — korumalı endpoint varsayımı yok"}, nil
	}
	if p.VariantStatus < 200 || p.VariantStatus >= 300 {
		return &Evidence{Verdict: VerdictReject, Note: "varyant 2xx değil — bypass yok"}, nil
	}
	if len(strings.TrimSpace(p.VariantBody)) < verbTamperMinBody {
		return &Evidence{Verdict: VerdictReject, Note: "varyant gövdesi anlamsız/boş (protokol yanıtı) — bypass sayılmaz"}, nil
	}
	m := baseline.NewDefaultModel()
	vb := string(m.Mask([]byte(p.VariantBody)))
	bb := string(m.Mask([]byte(p.BaselineBody)))
	if vb == bb {
		return &Evidence{Verdict: VerdictReject, Note: "varyant gövdesi baseline ile aynı (statü değişti, içerik değişmedi)"}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceFirm,
		Artifacts:              map[string]string{"baseline_status": itoa(int64(p.BaselineStatus)), "variant_status": itoa(int64(p.VariantStatus)), "variant": p.VariantMethod},
		Repeats:                1,
		ControlResult:          "baseline-denied",
		Note:                   "auth kısıtı metot/başlık varyantıyla atlandı (2xx + içerik) → firm (GASH-036 tavan)",
	}, nil
}
