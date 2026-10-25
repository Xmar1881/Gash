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

type scanSpinner struct {
	mu        sync.Mutex
	out       io.Writer
	th        theme
	target    string
	phase     string
	detail    string
	lastPhase string
	started   time.Time
	active    bool
	stopCh    chan struct{}
	doneCh    chan struct{}
	frames    []string
	lastLen   int
	isTTY     bool
}

func newScanSpinner(out io.Writer, target string) *scanSpinner {
	th := detectTheme(out)
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	if !th.tty {
		frames = []string{"-", "\\", "|", "/"}
	}
	return &scanSpinner{
		out:     out,
		th:      th,
		target:  target,
		phase:   "Başlatılıyor",
		detail:  "Hedef taranmaya hazırlanıyor...",
		frames:  frames,
		isTTY:   isInteractive(out),
		started: time.Now(),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

func (s *scanSpinner) Start() {
	s.mu.Lock()
	s.active = true
	s.started = time.Now()
	isTTY := s.isTTY
	s.mu.Unlock()

	if !isTTY {
		// Non-TTY (pipe, background task): print clean header
		fmt.Fprintf(s.out, "  › [Başlatılıyor] Hedef taranmaya hazırlanıyor...\n")
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

func (s *scanSpinner) OnProgress(phase, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isTTY {
		if phase != s.lastPhase {
			s.lastPhase = phase
			fmt.Fprintf(s.out, "  › [%s] %s\n", phase, detail)
		}
		s.phase = phase
		s.detail = detail
		return
	}

	s.phase = phase
	s.detail = detail
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

	detailClean := s.detail
	if utf8.RuneCountInString(detailClean) > 42 {
		runes := []rune(detailClean)
		detailClean = string(runes[:39]) + "..."
	}

	rawLine := fmt.Sprintf("  %s %s %-42s %s", frame, "["+s.phase+"]", detailClean, "("+timerStr+")")
	rawLen := utf8.RuneCountInString(rawLine)

	coloredLine := fmt.Sprintf("  %s %s %-42s %s", icon, phaseStr, detailClean, timeStr)

	padding := ""
	if s.lastLen > rawLen {
		padding = strings.Repeat(" ", s.lastLen-rawLen)
	}
	s.lastLen = rawLen

	fmt.Fprintf(s.out, "\r%s%s", coloredLine, padding)
}

func (s *scanSpinner) Stop() {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	isTTY := s.isTTY
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
		clearLine := "\r" + strings.Repeat(" ", s.lastLen+10) + "\r"
		doneMsg := fmt.Sprintf("  %s %s %s\n\n",
			s.th.good("✔"),
			s.th.bold("Tarama tamamlandı!"),
			s.th.muted("("+timerStr+")"),
		)
		fmt.Fprint(s.out, clearLine+doneMsg)
	} else {
		fmt.Fprintf(s.out, "  ✔ Tarama tamamlandı! (%s)\n\n", timerStr)
	}
}
