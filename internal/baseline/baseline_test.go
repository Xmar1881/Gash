// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package baseline

import (
	"net/http"
	"testing"
)

func TestWAFUntrusted(t *testing.T) {
	c := ClassifyStatic(200, http.Header{}, []byte("<html>cf-chl challenge</html>"))
	if !c.Untrusted {
		t.Fatal("WAF untrusted olmalı")
	}
}

func TestNormal(t *testing.T) {
	c := ClassifyStatic(200, http.Header{}, []byte("<html>hello</html>"))
	if c.Untrusted || c.Soft404 {
		t.Fatalf("normal sınıflandırılmalı: %+v", c)
	}
}

func TestMaskStable(t *testing.T) {
	m := NewDefaultModel()
	a := m.Mask([]byte(`<input name="csrf_token" value="abc123">`))
	b := m.Mask([]byte(`<input name="csrf_token" value="xyz789">`))
	if string(a) != string(b) {
		t.Fatalf("maske stabil olmalı:\n%s\n%s", a, b)
	}
}

func TestSoft404Learn(t *testing.T) {
	m := NewDefaultModel()
	m.LearnSoft404([][]byte{[]byte("same spa page")}, []int{200})
	c := m.Classify(200, http.Header{}, []byte("same spa page"))
	if !c.Soft404 {
		t.Fatalf("soft404 tanınmalı: %+v", c)
	}
}
