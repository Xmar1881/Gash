// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Spinner message keys. Engine progress keys are translated with the same
// catalogs, so the menu language switch also affects scan progress.
const (
	spinnerPhaseStarting = "progress.phase.starting"
	spinnerDetailPrepare = "progress.detail.starting.prepare"
	spinnerDetailDone    = "progress.detail.done"
)

type scanSpinner struct {
	mu           sync.Mutex
	out          io.Writer
	th           theme
	target       string
	phase        string
	detail       string
	started      time.Time
	phaseStarted time.Time
	active       bool
	stopCh       chan struct{}
	doneCh       chan struct{}
	frames       []string
	lastLen      int
	width        int
	isTTY        bool
}

func newScanSpinner(out io.Writer, target string) *scanSpinner {
	th := detectTheme(out)
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	if !th.tty {
		frames = []string{"-", "\\", "|", "/"}
	}
	lang := currentUILang()
	return &scanSpinner{
		out:     out,
		th:      th,
		target:  target,
		phase:   msg(lang, spinnerPhaseStarting),
		detail:  msg(lang, spinnerDetailPrepare),
		frames:  frames,
		isTTY:   isInteractive(out),
		started: time.Now(),
		width:   detectWidth(),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

func (s *scanSpinner) Start() {
	s.mu.Lock()
	s.active = true
	s.started = time.Now()
	s.phaseStarted = s.started
	isTTY := s.isTTY
	phase, detail := s.phase, s.detail
	s.mu.Unlock()

	if !isTTY {
		// Non-TTY (pipe, background task): one clean line per phase transition.
		fmt.Fprintf(s.out, "  › [%s] %s\n", phase, detail)
		return
	}

	go func() {
		defer close(s.doneCh)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()

		frameIdx := 0
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.draw(frameIdx)
				frameIdx = (frameIdx + 1) % len(s.frames)
			}
		}
	}()
}

// OnProgress records the current phase/detail. Keys are translated through the
// TR/EN catalogs; the engine never sends display text. A phase change freezes
// the previous phase with its last detail and measured duration.
func (s *scanSpinner) OnProgress(phaseKey, detailKey string, args ...any) {
	lang := currentUILang()
	phase := msg(lang, phaseKey)
	detail := msg(lang, detailKey, args...)

	s.mu.Lock()
	defer s.mu.Unlock()

	if phase != s.phase {
		if s.active && s.phase != "" {
			s.finalizePhaseLocked()
		}
		s.phase = phase
		s.phaseStarted = time.Now()
		s.detail = detail
		if !s.isTTY {
			fmt.Fprintf(s.out, "  › [%s] %s\n", phase, detail)
		}
		return
	}
	s.detail = detail
}

// finalizePhaseLocked writes the completed phase as a permanent line. It is
// called with s.mu held and resets the spinner line bookkeeping.
func (s *scanSpinner) finalizePhaseLocked() {
	if s.phase == "" {
		return
	}
	dur := time.Since(s.phaseStarted)
	detail := truncate(s.detail, s.detailBudget(s.phase))
	if s.isTTY {
		fmt.Fprintf(s.out, "\r\x1b[2K  %s %s %s %s\n",
			s.th.good("✔"),
			s.th.bold("["+s.phase+"]"),
			detail,
			s.th.muted("("+fmtDuration(dur)+")"))
	} else {
		fmt.Fprintf(s.out, "  ✔ [%s] %s (%s)\n", s.phase, detail, fmtDuration(dur))
	}
	s.lastLen = 0
}

func (s *scanSpinner) draw(frameIdx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return
	}

	elapsed := time.Since(s.started)
	mins := int(elapsed.Minutes())
	secs := int(elapsed.Seconds()) % 60
	timerStr := fmt.Sprintf("%02d:%02d", mins, secs)

	frame := s.frames[frameIdx]
	icon := s.th.accent(frame)
	phaseStr := s.th.bold("[" + s.phase + "]")
	timeStr := s.th.muted("(" + timerStr + ")")

	detailClean := truncate(s.detail, s.detailBudget(s.phase))
	budget := s.detailBudget(s.phase)

	rawLine := fmt.Sprintf("  %s %s %-*s %s", frame, "["+s.phase+"]", budget, detailClean, "("+timerStr+")")
	rawLen := utf8.RuneCountInString(rawLine)

	coloredLine := fmt.Sprintf("  %s %s %-*s %s", icon, phaseStr, budget, detailClean, timeStr)

	padding := ""
	if s.lastLen > rawLen {
		padding = strings.Repeat(" ", s.lastLen-rawLen)
	}
	s.lastLen = rawLen

	fmt.Fprintf(s.out, "\r%s%s", coloredLine, padding)
}

// detailBudget keeps the detail within the terminal width, leaving room for
// the spinner, phase label, and timer.
func (s *scanSpinner) detailBudget(phase string) int {
	width := s.width
	if width <= 0 {
		width = 76
	}
	budget := width - utf8.RuneCountInString(phase) - 18
	if budget < 24 {
		budget = 24
	}
	if budget > 90 {
		budget = 90
	}
	return budget
}

func (s *scanSpinner) Stop() {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	isTTY := s.isTTY
	if s.phase != "" {
		s.finalizePhaseLocked()
	}
	s.active = false
	if isTTY {
		close(s.stopCh)
	}
	s.mu.Unlock()

	if isTTY {
		<-s.doneCh
	}

	elapsed := time.Since(s.started)
	mins := int(elapsed.Minutes())
	secs := int(elapsed.Seconds()) % 60
	timerStr := fmt.Sprintf("%02d:%02d", mins, secs)

	if isTTY {
		doneMsg := fmt.Sprintf("  %s %s %s\n\n",
			s.th.good("✔"),
			s.th.bold(msg(currentUILang(), spinnerDetailDone)),
			s.th.muted("("+timerStr+")"),
		)
		fmt.Fprint(s.out, doneMsg)
	} else {
		fmt.Fprintf(s.out, "  ✔ %s (%s)\n\n", msg(currentUILang(), spinnerDetailDone), timerStr)
	}
}
