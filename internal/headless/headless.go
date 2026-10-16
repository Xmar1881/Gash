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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// DefaultTimeout bounds one VerifyDOM run (payload + control navigations).
const DefaultTimeout = 30 * time.Second

// Result is the browser proof consumed by oracle.ExecutionParams.
// What: Triggered = payload executed, ControlClean = neutral did not.
// Why: The oracle maps Triggered+ControlClean to confirmed; anything else
// rejects or stays below confirmed. No fake browser-confirmed.
type Result struct {
	// Triggered states the payload ran in the controlled browser.
	Triggered bool
	// ControlClean states the neutral control did not run.
	ControlClean bool
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
