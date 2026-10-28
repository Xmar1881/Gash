// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"fmt"
	"os"
	"time"
)

// gashLogoLines is the compact ANSI Shadow wordmark shown on the main menu.
// A logo is branding, not user-facing copy, so it stays language-neutral.
var gashLogoLines = []string{
	` ██████╗  █████╗ ███████╗██╗  ██╗`,
	`██╔════╝ ██╔══██╗██╔════╝██║  ██║`,
	`██║  ███╗███████║███████╗███████║`,
	`██║   ██║██╔══██║╚════██║██╔══██║`,
	`╚██████╔╝██║  ██║███████║██║  ██║`,
	` ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝`,
}

const logoFrameDelay = 55 * time.Millisecond

// logoColor interpolates the brand purple into the accent cyan per line.
func logoColor(line, total int) (int, int, int) {
	if total <= 1 {
		return 139, 92, 246
	}
	lerp := func(a, b int) int { return a + (b-a)*line/(total-1) }
	return lerp(139, 56), lerp(92, 225), lerp(246, 255)
}

// logoAnimationEnabled keeps animation on interactive color terminals only.
// Piped output, NO_COLOR, TERM=dumb, and GASH_NO_ANIMATION=1 stay static.
func (s *menuSession) logoAnimationEnabled() bool {
	if !s.th.tty || !s.th.color {
		return false
	}
	if os.Getenv("GASH_NO_ANIMATION") != "" {
		return false
	}
	return true
}

// printLogo paints the wordmark with a purple-to-cyan gradient. On an
// interactive color terminal it plays a short two-pass highlight sweep in
// place, then leaves the static wordmark; every other output path prints one
// frame.
func (s *menuSession) printLogo() {
	if !s.logoAnimationEnabled() {
		for i, line := range gashLogoLines {
			s.println("  " + s.logoLine(i, line, false))
		}
		return
	}
	for pass := 0; pass < 2; pass++ {
		for sweep := 0; sweep < len(gashLogoLines); sweep++ {
			if pass > 0 || sweep > 0 {
				fmt.Fprintf(s.out, "\033[%dA", len(gashLogoLines))
			}
			for i, line := range gashLogoLines {
				fmt.Fprintf(s.out, "\r\033[2K  %s\n", s.logoLine(i, line, i == sweep))
			}
			time.Sleep(logoFrameDelay)
		}
	}
	// Leave the unprefixed static frame behind instead of the last sweep.
	fmt.Fprintf(s.out, "\033[%dA", len(gashLogoLines))
	for i, line := range gashLogoLines {
		fmt.Fprintf(s.out, "\r\033[2K  %s\n", s.logoLine(i, line, false))
	}
}

func (s *menuSession) logoLine(line int, text string, highlight bool) string {
	if highlight {
		return s.th.paint("1;38;2;236;254;255", "1;97", text)
	}
	r, g, b := logoColor(line, len(gashLogoLines))
	return s.th.paint(fmt.Sprintf("1;38;2;%d;%d;%d", r, g, b), "35;1", text)
}
