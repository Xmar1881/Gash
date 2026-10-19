//go:build !deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import "context"

// RenderPage is the default-build stub: no browser driver is linked.
// What: Always returns ErrBrowserUnavailable, never fabricated HTML/URLs.
// Why: SPA discovery must degrade with an honest audit reason; rendering
// requires `-tags deep` plus a real Chrome binary.
func RenderPage(ctx context.Context, pageURL string, opts RenderOptions) (RenderedPage, error) {
	_ = ctx
	_ = pageURL
	_ = opts
	return RenderedPage{}, ErrBrowserUnavailable
}
