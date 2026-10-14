// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
	nethtml "golang.org/x/net/html"
)

// ReflectionParams benzersiz canary + bağlam analizidir (GASH-001/002/007/009/011/014/017).
type ReflectionParams struct {
	Canary                   string
	Contexts                 []string // html, attr, script, url
	RequireExecutableContext bool
	ControlBody              string // temiz-kontrol (confirmed için zorunlu)
}

// ReflectionOracle HTML tokenizer (x/net/html token stream) + bağlam makinesi kullanır.
// Tam DOM render YOKTUR.
type ReflectionOracle struct{}

func (ReflectionOracle) Name() string { return "reflection" }

// ContextOf canary'nin bağlamını döndürür
// (script/attr-executable/url/attr/style/html-text/comment/encoded/none).
//
// Sıralama disiplini (P0.1): önce tokenizer geçişi yapılır; yürütülebilir
// bağlam (script/attr-executable) her zaman kazanır — tek bir yürütülebilir
// yansıma bile bulgu için yeterlidir. Kodlanmışlık bitişikteki HTML-entity
// (`&lt;` vb.) varlığıyla sezilir; ham-tokenizer bağlamı bundan etkilenmez.
//
// Bilinen sınırlama (dürüstlük notu): canary alfabesi (`gash_` + hex) HTML-,
// URL- ve JS-kaçışlarında değişmez (identity) olduğundan çok katmanlı
// kodlama ayırt edilemez; `encoded` yalnızca bitişik entity izine dayanır.
// Bu durumda karar en fazla `tentative` olur, `firm` verilmez.
func ContextOf(body, canary string) string {
	if canary == "" || !strings.Contains(body, canary) {
		return "none"
	}
	// 1. Tokenizer geçişi: bağlam kümesi toplanır, en yüksek öncelik kazanır.
	// Öncelik: script/attr-executable (5) > url/attr (4) > style (3) >
	// html-text (2) > comment (1). Yorum içi `<script>` yazımı executable
	// sayılmaz (CommentToken ayrıca ele alınır).
	rank := map[string]int{
		"script": 5, "attr-executable": 5,
		"url": 4, "attr": 4,
		"style": 3, "html-text": 2, "comment": 1,
	}
	best, bestRank := "none", 0
	consider := func(ctx string) {
		if r, ok := rank[ctx]; ok && r > bestRank {
			best, bestRank = ctx, r
		}
	}
	tok := nethtml.NewTokenizer(strings.NewReader(body))
	inScript, inStyle := false, false
	tokenizerOK := false
loop:
	for {
		tt := tok.Next()
		switch tt {
		case nethtml.ErrorToken:
			break loop
		case nethtml.CommentToken:
			tokenizerOK = true
			if strings.Contains(string(tok.Text()), canary) {
				consider("comment")
			}
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			tokenizerOK = true
			tn, hasAttr := tok.TagName()
			tag := string(tn)
			if strings.EqualFold(tag, "script") {
				inScript = true
			}
			if strings.EqualFold(tag, "style") {
				inStyle = true
			}
			if hasAttr {
				for {
					k, v, more := tok.TagAttr()
					ks, vs := string(k), string(v)
					if strings.Contains(vs, canary) {
						lk := strings.ToLower(ks)
						if strings.HasPrefix(lk, "on") {
							consider("attr-executable")
						} else if lk == "href" || lk == "src" || lk == "action" {
							consider("url")
						} else {
							consider("attr")
						}
					}
					if !more {
						break
					}
				}
			}
		case nethtml.EndTagToken:
			tokenizerOK = true
			tn, _ := tok.TagName()
			if strings.EqualFold(string(tn), "script") {
				inScript = false
			}
			if strings.EqualFold(string(tn), "style") {
				inStyle = false
			}
		case nethtml.TextToken:
			tokenizerOK = true
			txt := string(tok.Text())
			if !strings.Contains(txt, canary) {
				continue
			}
			switch {
			case inScript:
				consider("script")
			case inStyle:
				consider("style")
			default:
				consider("html-text")
			}
		}
	}
	if bestRank >= 5 {
		return best // yürütülebilir bağlam kesindir; kodlama bitişikliği aranmaz.
	}
	// 2. Kodlanmışlık sezgisi: canary oluşumunun ±48 karakter penceresinde
	// HTML-entity (`&lt; &gt; &amp; &quot; &#...;`) veya JS-unicode kaçışı
	// (`\u...`) varsa yansıma kodlanmış sayılır → en fazla tentative.
	if likelyEncoded(body, canary) {
		return "encoded"
	}
	if best != "none" {
		return best
	}
	if !tokenizerOK {
		return "none"
	}
	// 3. Bozuk HTML geri dönüşü: tokenizer hiç token üretemediyse (tokenizerOK
	// false iken best==none olur, yukarıda dönüldü) buraya ulaşılmaz; bozuk
	// ama kısmen okunabilen gövdelerde pencere sezgisi uygulanır.
	return fallbackContext(body, canary)
}

// likelyEncoded canary çevresinde kodlama izi arar (bitişiklik sezgisi).
func likelyEncoded(body, canary string) bool {
	markers := []string{"&lt;", "&gt;", "&amp;", "&quot;", "&#", `\u`}
	from := 0
	for {
		idx := strings.Index(body[from:], canary)
		if idx < 0 {
			return false
		}
		abs := from + idx
		lo := abs - 48
		if lo < 0 {
			lo = 0
		}
		hi := abs + len(canary) + 48
		if hi > len(body) {
			hi = len(body)
		}
		window := strings.ToLower(body[lo:hi])
		for _, m := range markers {
			if strings.Contains(window, m) {
				return true
			}
		}
		from = abs + len(canary)
		if from >= len(body) {
			return false
		}
	}
}

// fallbackContext bozuk HTML için pencere sezgisidir (son çare).
// Not: `href=` komşuluğu tek başına `url` kararı vermez; yalnızca pencere
// içinde canary ile aynı attribute değerindeyse dikkate alınır. Belirsizlikte
// html-text döner (tentative tavanı Verify'da uygulanır).
func fallbackContext(body, canary string) string {
	lower := strings.ToLower(body)
	idx := strings.Index(body, canary)
	if idx < 0 {
		return "none"
	}
	window := body[max(0, idx-200):min(len(body), idx+200)]
	if strings.Contains(lower, "<script") && strings.Contains(window, canary) {
		return "script"
	}
	if strings.Contains(window, "onerror=") || strings.Contains(window, "onload=") || strings.Contains(window, "onclick=") {
		return "attr-executable"
	}
	if strings.Contains(window, "=") && strings.Contains(window, canary) {
		return "attr"
	}
	return "html-text"
}

// Verify yansıma + bağlam + kontrol üçlüsünü uygular (G-02: kontrolsüz confirmed YOK).
func (ReflectionOracle) Verify(ctx context.Context, body string, headers http.Header, cls baseline.Classification, tainted bool, p ReflectionParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if p.Canary == "" {
		return &Evidence{Verdict: VerdictReject, Note: "boş canary"}, nil
	}
	if !strings.Contains(body, p.Canary) {
		return &Evidence{Verdict: VerdictReject, Note: "yansıma yok"}, nil
	}
	bctx := ContextOf(body, p.Canary)
	art := map[string]string{"context": bctx, "canary": p.Canary}
	switch bctx {
	case "encoded":
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "encode'lu yansıma → tentative"}, nil
	case "comment":
		return &Evidence{Verdict: VerdictReject, Note: "yorum içi yansıma yürütülmez — kanıt olamaz"}, nil
	case "style":
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "CSS bağlamı statik analizle yürütülebilirlik kanıtlanamaz → tentative"}, nil
	case "none":
		return &Evidence{Verdict: VerdictReject, Note: "yansıma bağlamı çözülemedi"}, nil
	case "html-text":
		if p.RequireExecutableContext {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "text bağlam tek başına firm vermez → tentative"}, nil
		}
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: art, Note: "text yansıma"}, nil
	case "script", "attr-executable":
		// Kontrol: temiz payload aynı bağlamda yürütülebilir değil.
		if p.ControlBody != "" && ContextOf(p.ControlBody, p.Canary) == bctx {
			return &Evidence{Verdict: VerdictReject, Note: "kontrol de aynı executable bağlamda — ayırt edici değil"}, nil
		}
		if p.ControlBody == "" {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: art, Note: "kontrolsüz executable yansıma → firm (confirmed için kontrol zorunlu)"}, nil
		}
		// Kontrolde canary yoksa veya farklı bağlamdaysa confirmed.
		if strings.Contains(p.ControlBody, p.Canary) {
			return &Evidence{Verdict: VerdictReject, Note: "kontrolde de canary executable"}, nil
		}
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceConfirmed, Artifacts: art, Repeats: 1, ControlResult: "clean", Note: "bağlamsal yürütülebilir yansıma + kontrol"}, nil
	case "attr", "url":
		if p.RequireExecutableContext {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art, Note: "yürütülebilir olmayan bağlam → tentative"}, nil
		}
		if p.ControlBody != "" && !strings.Contains(p.ControlBody, p.Canary) {
			return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceConfirmed, Artifacts: art, Repeats: 1, ControlResult: "clean"}, nil
		}
		return &Evidence{Verdict: VerdictAccept, ConfidenceContribution: plugin.ConfidenceFirm, Artifacts: art}, nil
	default:
		return &Evidence{Verdict: VerdictReject, Note: fmt.Sprintf("bilinmeyen bağlam %q", bctx)}, nil
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
