//go:build !deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"errors"
	"testing"
)

func TestStubRenderUnavailable(t *testing.T) {
	_, err := RenderPage(t.Context(), "http://127.0.0.1/", RenderOptions{})
	if !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("default build RenderPage error = %v, want ErrBrowserUnavailable", err)
	}
}
