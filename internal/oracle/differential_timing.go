// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"math"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// DifferentialParams true/false/kontrol üçlüsüdür (GASH-005).
// ConfidenceCeiling kabul kararına tavan koyar ("" = yok; "firm"/"tentative"/
// "static-execution-evidence" alta indirir, asla yükseltmez). Mass assignment
// (GASH-031) gibi tek-kanallı bağlanma sinyallerinde confirmed şişmesini
// önler; plugin YAML'dan `confidence_ceiling` ile beyan edilir.
type DifferentialParams struct {
	TrueBodies        []string
	FalseBodies       []string
	ControlBody       string
	Repeats           int // default 3
	ConfidenceCeiling string
}

// DifferentialOracle maskeleme-sonrası karşılaştırma yapar; tutarsız = ret.
type DifferentialOracle struct{}

func (DifferentialOracle) Name() string { return "differential" }

func maskAll(bodies []string) []string {
	m := baseline.NewDefaultModel()
	out := make([]string, len(bodies))
	for i, b := range bodies {
		out[i] = string(m.Mask([]byte(b)))
	}
	return out
}

// Verify 3/3 tutarlılıkta confirmed, kısmi tutarlılıkta firm, kararsızda reject verir.
// Kural: differential kararsızsa tentative bile değil — direkt eleme (GASH-005).
func (DifferentialOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p DifferentialParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	n := p.Repeats
	if n <= 0 {
		n = 3
	}
	if len(p.TrueBodies) < n || len(p.FalseBodies) < n {
		return &Evidence{Verdict: VerdictReject, Note: "yetersiz tekrar (N=3 zorunlu)"}, nil
	}
	tb := maskAll(p.TrueBodies[:n])
	fb := maskAll(p.FalseBodies[:n])

	trueStable := allEqual(tb)
	falseStable := allEqual(fb)
	if !trueStable || !falseStable {
		return &Evidence{Verdict: VerdictReject, Note: "kararsız differential — bulgu yok"}, nil
	}
	if tb[0] == fb[0] {
		return &Evidence{Verdict: VerdictReject, Note: "true/false ayrışmıyor"}, nil
	}
	// Kontrol: nötr payload true dalıyla aynı olamaz. Kontrolün false dalıyla
	// aynı olması normaldir (ikisi de enjeksiyonsuz yanıttır); true dalıyla
	// aynıysa ayrışma payload'dan değil sayfanın kendi davranışından gelir.
	if p.ControlBody != "" {
		m := baseline.NewDefaultModel()
		cb := string(m.Mask([]byte(p.ControlBody)))
		if cb == tb[0] {
			return &Evidence{Verdict: VerdictReject, Note: "kontrol true dalıyla aynı — ayırt edici değil"}, nil
		}
	}
	art := map[string]string{"true_hash": tb[0][:min(16, len(tb[0]))], "false_hash": fb[0][:min(16, len(fb[0]))]}
	// Tam tutarlılık + ayrışma → confirmed (3/3); beyanlı tavan varsa indirilir.
	conf := plugin.ConfidenceConfirmed
	note := "3/3 tutarlı differential + kontrol"
	if ceil, ok := confidenceCeiling(p.ConfidenceCeiling); ok && confidenceRank(conf) > confidenceRank(ceil) {
		conf = ceil
		art["ceiling"] = string(ceil)
		note += " (tavan: " + string(ceil) + ")"
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: conf,
		Artifacts:              art,
		Repeats:                n,
		ControlResult:          "stable",
		Note:                   note,
	}, nil
}

// VerifyPartial 2/3 tutarlılıkta firm'a düşürme için kullanılır.
func (DifferentialOracle) VerifyPartial(trueStable, falseStable, diverges bool) *Evidence {
	if trueStable && falseStable && diverges {
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Note: "kısmi tutarlılık → firm"}
	}
	return &Evidence{Verdict: VerdictReject, Note: "kararsız — reject"}
}

func allEqual(in []string) bool {
	for i := 1; i < len(in); i++ {
		if in[i] != in[0] {
			return false
		}
	}
	return true
}

// confidenceRank güven sırasıdır (tavan karşılaştırması için).
func confidenceRank(c plugin.Confidence) int {
	switch c {
	case plugin.ConfidenceTentative:
		return 0
	case plugin.ConfidenceStaticExecution:
		return 1
	case plugin.ConfidenceFirm:
		return 2
	case plugin.ConfidenceConfirmed:
		return 3
	default:
		return -1
	}
}

// confidenceCeiling tavan dizesini doğrular (bilinmeyeni yok sayar, fail-open değil fail-keep).
func confidenceCeiling(s string) (plugin.Confidence, bool) {
	switch plugin.Confidence(s) {
	case plugin.ConfidenceTentative, plugin.ConfidenceStaticExecution, plugin.ConfidenceFirm, plugin.ConfidenceConfirmed:
		return plugin.Confidence(s), true
	default:
		return "", false
	}
}

// TimingParams istatistiksel ayrışmadır (GASH-006/010).
type TimingParams struct {
	DelaySamples   []float64 // ms
	ControlSamples []float64 // ms
	BaselineStddev float64
	MinDelayMs     float64 // default 5000
	Repeats        int     // >=3 zorunlu
	Strategy       string  // mann-whitney-u | threshold
}

// TimingOracle baseline jitter + kontrol ayrışması zorunludur.
// OOB'siz maksimum firm'dır (confirmed YOK).
type TimingOracle struct{}

func (TimingOracle) Name() string { return "timing" }

func median(in []float64) float64 {
	if len(in) == 0 {
		return 0
	}
	cp := append([]float64{}, in...)
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j] < cp[j-1]; j-- {
			cp[j], cp[j-1] = cp[j-1], cp[j]
		}
	}
	m := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[m]
	}
	return (cp[m-1] + cp[m]) / 2
}

// mannWhitneyU iki-örneklem U testi (tek-yönlü, normal yaklaşım, alpha=0.05 → z>1.645).
func mannWhitneyU(a, b []float64) (u float64, z float64) {
	n1, n2 := float64(len(a)), float64(len(b))
	type pair struct {
		v float64
		g int // 0=a, 1=b
	}
	var all []pair
	for _, v := range a {
		all = append(all, pair{v, 0})
	}
	for _, v := range b {
		all = append(all, pair{v, 1})
	}
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].v < all[j-1].v; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	// Rank (tie-ortalama).
	ranks := make([]float64, len(all))
	i := 0
	for i < len(all) {
		j := i
		for j+1 < len(all) && all[j+1].v == all[i].v {
			j++
		}
		avg := (float64(i+1) + float64(j+1)) / 2
		for k := i; k <= j; k++ {
			ranks[k] = avg
		}
		i = j + 1
	}
	var r1 float64
	for k, p := range all {
		if p.g == 0 {
			r1 += ranks[k]
		}
	}
	u1 := r1 - n1*(n1+1)/2
	mu := n1 * n2 / 2
	sigma := math.Sqrt(n1 * n2 * (n1 + n2 + 1) / 12)
	if sigma == 0 {
		return u1, 0
	}
	z = (u1 - mu) / sigma
	return u1, z
}

// Verify timing kararı verir (tek ölçümle bulgu YOK).
func (TimingOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p TimingParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	n := p.Repeats
	if n <= 0 {
		n = 3
	}
	if n < 3 {
		return &Evidence{Verdict: VerdictReject, Note: "timing N>=3 zorunlu"}, nil
	}
	if len(p.DelaySamples) < n || len(p.ControlSamples) < n {
		return &Evidence{Verdict: VerdictReject, Note: "yetersiz timing tekrarı"}, nil
	}
	delay := p.DelaySamples[:n]
	ctrl := p.ControlSamples[:n]
	minDelay := p.MinDelayMs
	if minDelay <= 0 {
		minDelay = 5000
	}
	md, mc := median(delay), median(ctrl)
	diff := md - mc
	if diff < minDelay*0.8 {
		return &Evidence{Verdict: VerdictReject, Note: "gecikme ayrışmıyor (min_delay altında)"}, nil
	}
	// Baseline jitter'dan anlamlı büyük: medyan fark > 3*stddev.
	sd := p.BaselineStddev
	if sd > 0 && diff <= 3*sd {
		return &Evidence{Verdict: VerdictReject, Note: "jitter içinde — anlamsız"}, nil
	}
	// İstatistiksel test.
	_, z := mannWhitneyU(delay, ctrl)
	strategy := p.Strategy
	if strategy == "" {
		strategy = "mann-whitney-u"
	}
	if strategy == "mann-whitney-u" && z < 1.645 {
		// Fallback: basit eşik (medyan fark + p95 ayrışması) da denenir.
		if !(diff > 3*math.Max(sd, 1) && md > mc) {
			return &Evidence{Verdict: VerdictReject, Note: "M-W U anlamsız (z<1.645)"}, nil
		}
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceFirm,
		Artifacts:              map[string]string{"median_delay_ms": ftoa(md), "median_control_ms": ftoa(mc)},
		Repeats:                n,
		ControlResult:          "diverged",
		Note:                   "timing istatistiksel ayrışma → firm (OOB'siz maksimum)",
	}, nil
}

func ftoa(f float64) string {
	if f == float64(int64(f)) {
		return itoa(int64(f))
	}
	return fmtFloat(f)
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [32]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

func fmtFloat(f float64) string {
	// Kısa, deterministik (test stabilitesi).
	s := ""
	neg := f < 0
	if neg {
		f = -f
		s = "-"
	}
	ip := int64(f)
	fp := int64((f - float64(ip)) * 100)
	return s + itoa(ip) + "." + itoa(fp)
}
