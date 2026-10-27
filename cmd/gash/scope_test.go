// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import "testing"

func TestSameSiteDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://www.carcentercassel.de/path?q=1", "carcentercassel.de"},
		{"https://de.example.co.uk/a", "example.co.uk"},
		{"http://127.0.0.1:8080/x", "127.0.0.1"},
		{"localhost:3000", "localhost"},
		{"https://foo.github.io/repo", "foo.github.io"},
		{"example.com", "example.com"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := sameSiteDomain(tc.in); got != tc.want {
			t.Fatalf("sameSiteDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"a", "", "b", "a", " b "})
	want := []string{"a", "b"}
	if len(got) != len(want) {
		t.Fatalf("uniqueStrings = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("uniqueStrings = %v, want %v", got, want)
		}
	}
}
