// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"fmt"
	"html"
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

// ContextOf canary'nin bağlamını döndürür (body/attr/script/url/encoded/text/none).
func ContextOf(body, canary string) string {
	if canary == "" || !strings.Contains(body, canary) {
		return "none"
	}
	// Encode durumu: HTML-entity'li yansıma → encoded.
	if strings.Contains(body, html.EscapeString(canary)) && html.EscapeString(canary) != canary {
		// Ham da varsa executable olabilir; önce ham bağlamı çöz.
		if strings.Count(body, canary) == strings.Count(body, html.EscapeString(canary)) {
			return "encoded"
		}
	}
	// URL bağlamı: href/src/action içinde mi?
	lower := strings.ToLower(body)
	idx := strings.Index(body, canary)
	window := body[max(0, idx-200):min(len(body), idx+200)]
	wl := strings.ToLower(window)
	if strings.Contains(wl, "href=") || strings.Contains(wl, "src=") || strings.Contains(wl, "action=") {
		return "url"
	}
	// Tokenizer ile script/attr ayrımı.
	tok := nethtml.NewTokenizer(strings.NewReader(body))
	inScript := false
	for {
		tt := tok.Next()
		switch tt {
		case nethtml.ErrorToken:
			// Fallback: string heuristiği.
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
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			tn, hasAttr := tok.TagName()
			tag := string(tn)
			if strings.EqualFold(tag, "script") {
				inScript = true
			}
			if hasAttr {
				for {
					k, v, more := tok.TagAttr()
					ks, vs := string(k), string(v)
					if strings.Contains(vs, canary) {
						lk := strings.ToLower(ks)
						if strings.HasPrefix(lk, "on") {
							return "attr-executable"
						}
						if lk == "href" || lk == "src" || lk == "action" {
							return "url"
						}
						return "attr"
					}
					if !more {
						break
					}
				}
			}
		case nethtml.EndTagToken:
			tn, _ := tok.TagName()
			if strings.EqualFold(string(tn), "script") {
				inScript = false
			}
		case nethtml.TextToken:
			txt := string(tok.Text())
			if strings.Contains(txt, canary) && inScript {
				return "script"
			}
			if strings.Contains(txt, canary) {
				return "html-text"
			}
		}
	}
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
