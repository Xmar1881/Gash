// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"strings"

	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/headless"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// browserVerifier resolves the verifier function.
// What: test seam first (BrowserVerifyFunc), real headless second; a reason
// string explains an honest skip when no verifier is available.
// Why: Default builds link no browser; the pass must degrade with an audit
// reason, never fabricate a browser-confirmed verdict.
func (e *Engine) browserVerifier() (func(ctx context.Context, payloadURL, controlURL string) (bool, bool, error), string) {
	if e.cfg.BrowserVerifyFunc != nil {
		return e.cfg.BrowserVerifyFunc, ""
	}
	if !headless.Supported() {
		return nil, "skipped (browser-verify requires a -tags deep build; default build links no browser)"
	}
	if !headless.Available() {
		return nil, "skipped (browser-verify found no Chrome binary)"
	}
	return func(ctx context.Context, payloadURL, controlURL string) (bool, bool, error) {
		res, err := headless.VerifyXSS(ctx, payloadURL, controlURL, headless.DefaultTimeout)
		if err != nil {
			return false, false, err
		}
		if verr := res.VerifyError(); verr != nil {
			return false, false, verr
		}
		return res.Triggered, res.ControlClean, nil
	}, ""
}

// browserEligible selects findings the generic pass may verify.
// What: GASH-001 static-execution findings and GASH-003 DOM findings with a
// GET/query or GET/fragment injection point can have payload and control URLs
// reconstructed.
// Why: Body-borne or stored payloads need workflow-specific control URLs and
// are wired at their oracle binding (stored binding controlUrl option);
// reconstructing them here would risk a fake control.
func browserEligible(f *finding.Finding) bool {
	if f == nil {
		return false
	}
	if f.RuleID != "GASH-001" && f.RuleID != "GASH-003" {
		return false
	}
	if f.Confidence == plugin.ConfidenceConfirmed {
		return false
	}
	if f.RuleID == "GASH-001" && f.Confidence != plugin.ConfidenceStaticExecution {
		return false
	}
	if f.RuleID == "GASH-003" &&
		f.Confidence != plugin.ConfidenceFirm &&
		f.Confidence != plugin.ConfidenceTentative {
		return false
	}
	ip := f.InjectionPoint
	location := strings.ToLower(strings.TrimSpace(ip.ParamLocation))
	if (location != "query" && location != "fragment") || ip.ParamName == "" || ip.Value == "" {
		return false
	}
	if ip.Method != "" && !strings.EqualFold(ip.Method, http.MethodGet) {
		return false
	}
	return strings.TrimSpace(f.Target) != ""
}

// verifyBrowserFindings upgrades eligible findings to confirmed only on a
// real browser trigger plus a clean control.
// What: Reconstructs payload/control URLs, runs the verifier, and mutates the
// finding in place. Trigger without clean control, no trigger, or verifier
// error all keep the existing (static) tier untouched.
// Why: The evidence ladder must never be inflated: confirmed is reserved for
// reproducible browser execution with an indistinguishable control excluded.
func (e *Engine) verifyBrowserFindings(ctx context.Context, findings []*finding.Finding) []plugin.SkippedPlugin {
	if !e.cfg.BrowserVerify || len(findings) == 0 {
		return nil
	}
	verifier, skipReason := e.browserVerifier()
	if verifier == nil {
		return []plugin.SkippedPlugin{{PluginID: "browser-verify", Reason: skipReason}}
	}
	var skipped []plugin.SkippedPlugin
	errorReported := false
	for _, f := range findings {
		if !browserEligible(f) {
			continue
		}
		point := loader.JSPoint{
			URL: f.Target, Method: http.MethodGet,
			ParamName: f.InjectionPoint.ParamName, ParamLocation: f.InjectionPoint.ParamLocation,
			Value: f.InjectionPoint.Value,
		}
		payloadURL := pointValueURL(f.Target, point, f.InjectionPoint.Value)
		controlURL := pointValueURL(f.Target, point, controlNeutralValue)
		if payloadURL == "" || controlURL == "" || controlURL == payloadURL {
			continue
		}
		triggered, clean, verr := verifier(ctx, payloadURL, controlURL)
		if verr != nil {
			if !errorReported {
				skipped = append(skipped, plugin.SkippedPlugin{PluginID: "browser-verify", Reason: "error: " + verr.Error()})
				errorReported = true
			}
			continue
		}
		if f.Evidence == nil {
			f.Evidence = map[string]string{}
		}
		if triggered && clean {
			f.Confidence = plugin.ConfidenceConfirmed
			f.Evidence["execution"] = "browser-confirmed"
			if !strings.Contains(f.Note, "browser-confirmed") {
				f.Note = strings.TrimSpace(f.Note + "; browser-confirmed (triggered + clean control)")
			}
			f.VerificationMethod = strings.TrimSpace(f.VerificationMethod + ", browser-verified")
			if f.Reproducibility != nil {
				f.Reproducibility["note"] = f.Note
			}
		} else if triggered {
			f.Evidence["browser_verify"] = "control-dirty"
		} else {
			f.Evidence["browser_verify"] = "not-triggered"
		}
		// One controlled payload/control pair never proves page-wide safety.
		f.Evidence["browser_verify_scope"] = "tested payload/control pair only"
		// Evidence map participates in the fingerprint; keep dedup stable.
		f.Fingerprint = finding.Fingerprint(f)
	}
	return skipped
}
