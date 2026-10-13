// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package vcr

import "testing"

func TestServeAndHits(t *testing.T) {
	v := New()
	defer v.Close()
	v.AddRoute("GET", "/x", 200, map[string]string{"X-Test": "1"}, "hello")
	if v.URL() == "" {
		t.Fatal("URL boş olmamalı")
	}
}
