// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package headless verifies DOM execution in a controlled browser.
// What: Headless Chrome proof for GASH-003 (Triggered + ControlClean).
// Why: Static sink/source caps at firm; confirmed requires a real browser
// run plus a clean control. This file holds the shared types and Chrome
// discovery; the actual CDP driver lives behind the `deep` build tag so the
// default binary stays light (chromedp only in -tags deep builds).
package headless

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// DefaultTimeout bounds one VerifyDOM run (payload + control navigations).
const DefaultTimeout = 30 * time.Second

// Outcome is the honest result of one controlled browser proof.
// What: Confirmed requires payload execution plus a clean control; a blocked
// or failed navigation is never reported as not-vulnerable.
// Why: Callers need one explicit classification so WAF blocks and browser
// errors cannot silently turn into false negatives.
type Outcome string

const (
	// OutcomeConfirmed means the payload executed and the control stayed clean.
	OutcomeConfirmed Outcome = "confirmed"
	// OutcomeCandidate means execution was observed but the control also ran.
	OutcomeCandidate Outcome = "candidate"
	// OutcomeUnverified means the browser could not distinguish the two pages.
	OutcomeUnverified Outcome = "unverified"
	// OutcomeNotVulnerable means a clean control and no payload execution for
	// the supplied payload/control pair. It is not a page-wide safety claim.
	OutcomeNotVulnerable Outcome = "not_vulnerable"
	// OutcomeBlocked means the browser received an auth/WAF block status.
	OutcomeBlocked Outcome = "blocked"
	// OutcomeError means the browser hit a server or navigation error.
	OutcomeError Outcome = "error"
)

// Result is the browser proof consumed by oracle.ExecutionParams.
// What: Triggered = payload executed, ControlClean = neutral did not;
// PayloadStatus/ControlStatus carry the main document HTTP status when the
// deep driver observed one (zero means unavailable).
// Why: The oracle maps Triggered+ControlClean to confirmed; anything else
// rejects or stays below confirmed. No fake browser-confirmed.
type Result struct {
	// Triggered states the payload ran in the controlled browser.
	Triggered bool
	// ControlClean states the neutral control did not run.
	ControlClean bool
	// PayloadStatus is the payload navigation's main document status.
	PayloadStatus int
	// ControlStatus is the control navigation's main document status.
	ControlStatus int
}

// Outcome classifies a browser proof without inflating evidence.
// What: A blocked/error status invalidates the comparison before a trigger is
// trusted; execution only counts when both docs produced usable statuses.
// Why: A 403/429/5xx page that shows no canary must not be recorded as "not
// vulnerable", and a blocked control cannot serve as proof that the payload's
// execution was payload-specific.
func (r Result) Outcome() Outcome {
	switch {
	case failedStatus(r.PayloadStatus) || failedStatus(r.ControlStatus):
		return OutcomeError
	case blockedStatus(r.PayloadStatus) || blockedStatus(r.ControlStatus):
		return OutcomeBlocked
	case r.Triggered && r.ControlClean:
		return OutcomeConfirmed
	case r.Triggered:
		return OutcomeCandidate
	case r.ControlClean:
		return OutcomeNotVulnerable
	default:
		return OutcomeUnverified
	}
}

// HTTPReason maps a main-document status to a stable, non-judgmental reason
// code. A 403 is "forbidden" (it may be authorization or a WAF), 429 is
// "rate_limited", and 5xx is "server_error"; callers must not collapse them.
func HTTPReason(status int) string {
	switch status {
	case 401:
		return "auth_required"
	case 403:
		return "forbidden"
	case 407:
		return "proxy_auth_required"
	case 408:
		return "request_timeout"
	case 429:
		return "rate_limited"
	case 451:
		return "legal_block"
	}
	if status >= 500 && status <= 599 {
		return "server_error"
	}
	return ""
}

// Reason returns the status reason for the side that prevented a verdict.
// What: payload wins over control; empty means no status-based reason.
// Why: Reports need "payload_forbidden" or "control_rate_limited", not a
// single vague "blocked" label.
func (r Result) Reason() string {
	if reason := HTTPReason(r.PayloadStatus); reason != "" {
		return "payload_" + reason
	}
	if reason := HTTPReason(r.ControlStatus); reason != "" {
		return "control_" + reason
	}
	return ""
}

// StatusError is the structured error for a blocked or failed browser proof.
// What: Carries the outcome, stable reason code, and both document statuses.
// Why: Engine and benchmark reports can preserve the reason code instead of
// parsing a free-form error string.
type StatusError struct {
	Outcome       Outcome
	Reason        string
	PayloadStatus int
	ControlStatus int
}

func (e *StatusError) Error() string {
	reason := e.Reason
	if reason == "" {
		reason = "unclassified"
	}
	return fmt.Sprintf("browser verification %s: reason=%s payload_status=%d control_status=%d",
		e.Outcome, reason, e.PayloadStatus, e.ControlStatus)
}

// VerifyError returns a structured error only for blocked/failed proofs.
// Why: Callers must treat these as unverified, never as a clean negative.
func (r Result) VerifyError() error {
	switch r.Outcome() {
	case OutcomeBlocked, OutcomeError:
		return &StatusError{
			Outcome:       r.Outcome(),
			Reason:        r.Reason(),
			PayloadStatus: r.PayloadStatus,
			ControlStatus: r.ControlStatus,
		}
	default:
		return nil
	}
}

// blockedStatus reports auth/throttle block statuses that prevent a verdict.
func blockedStatus(status int) bool {
	switch status {
	case 401, 403, 407, 429, 451:
		return true
	default:
		return false
	}
}

// failedStatus reports transport/server statuses that prevent a verdict.
func failedStatus(status int) bool {
	return status == 408 || (status >= 500 && status <= 599)
}

// newCanaryToken returns a fresh per-proof token. The bootstrap script stamps
// it only when a payload actually executes, so a DOM insertion or a stale
// window flag from another run cannot satisfy the probe.
func newCanaryToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("headless: canary token: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// xssCanaryBootstrap installs the execution observer before any page script.
// What: marks alert/confirm/prompt calls and writes to window.__gashCanary
// with the run token. AddScriptToEvaluateOnNewDocument runs in the main world
// before page code, so the payload cannot bypass the marker by defining its
// own value.
// Why: A element insert (e.g. <div id="__gash_canary">) is not execution; only
// an actual JS side effect should feed the confirmed verdict.
func xssCanaryBootstrap(token string) string {
	return fmt.Sprintf(`(function(){
  try {
    var token = %q;
    window.__gashRunToken = token;
    var origAlert = window.alert;
    window.alert = function(){
      try { window.__gashDialogToken = token; } catch(e) {}
      return origAlert.apply(window, arguments);
    };
    var origConfirm = window.confirm;
    window.confirm = function(){
      try { window.__gashDialogToken = token; } catch(e) {}
      return origConfirm.apply(window, arguments);
    };
    var origPrompt = window.prompt;
    window.prompt = function(){
      try { window.__gashDialogToken = token; } catch(e) {}
      return origPrompt.apply(window, arguments);
    };
    var canary = false;
    try {
      Object.defineProperty(window, '__gashCanary', {
        configurable: false,
        get: function(){ return canary; },
        set: function(v){
          canary = v;
          if (v === true) { try { window.__gashCanaryToken = token; } catch(e) {} }
        }
      });
    } catch(e) {}
  } catch(e) {}
})();`, token)
}

// xssCanaryProbe checks the token-stamped side effects in the top document and
// same-origin frames. Cross-origin frames are intentionally not inspectable;
// the controlled control navigation remains the corroborating evidence.
func xssCanaryProbe(token string) string {
	return fmt.Sprintf(`(function(){
  try {
    if (window.__gashRunToken !== %q) return false;
    if (window.__gashCanaryToken === %q || window.__gashDialogToken === %q) return true;
    for (var i = 0; i < window.frames.length; i++) {
      try {
        var w = window.frames[i];
        if (w.__gashCanaryToken === %q || w.__gashDialogToken === %q) return true;
      } catch(e) {}
    }
  } catch(e) {}
  return false;
})()`, token, token, token, token, token)
}

// chromeCandidates lists well-known Chrome locations across platforms (Windows, Linux, macOS).
func chromeCandidates() []string {
	var candidates []string
	if exe := os.Getenv("CHROME_BIN"); exe != "" {
		candidates = append(candidates, exe)
	}
	if exe := os.Getenv("CHROME_PATH"); exe != "" {
		candidates = append(candidates, exe)
	}
	switch runtime.GOOS {
	case "windows":
		candidates = append(candidates,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			filepath.Join(os.Getenv("LocalAppData"), `Google\Chrome\Application\chrome.exe`),
		)
	case "darwin":
		candidates = append(candidates,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		)
	default: // linux, bsd, etc.
		candidates = append(candidates,
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/opt/google/chrome/chrome",
			"/opt/google/chrome/google-chrome",
		)
	}
	return candidates
}

// FindChrome returns the first existing Chrome binary path, or "".
// What: Checks environment, OS-specific standard locations, then searches PATH.
// Why: Enables headless DOM verification across Linux CI, Windows, and macOS.
func FindChrome() string {
	for _, p := range chromeCandidates() {
		if p != "" {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "chrome.exe", "chromium.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// Available reports whether a Chrome binary was found for headless runs.
func Available() bool { return FindChrome() != "" }
