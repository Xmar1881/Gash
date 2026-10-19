// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeObservedURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "lowercases scheme and host and drops fragment", in: "HTTP://Example.COM/Path?q=1#frag", want: "http://example.com/Path?q=1"},
		{name: "trims whitespace", in: "  https://example.com/a  ", want: "https://example.com/a"},
		{name: "strips userinfo", in: "http://user:pass@example.com/x", want: "http://example.com/x"},
		{name: "rejects data scheme", in: "data:text/html,hi", want: ""},
		{name: "rejects javascript scheme", in: "javascript:alert(1)", want: ""},
		{name: "rejects scheme relative", in: "//example.com/x", want: ""},
		{name: "rejects empty", in: "", want: ""},
		{name: "rejects missing host", in: "http://", want: ""},
		{name: "rejects ftp", in: "ftp://example.com/x", want: ""},
		{name: "rejects overlong", in: "http://example.com/" + strings.Repeat("a", maxObservedURLLen), want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeObservedURL(tc.in); got != tc.want {
				t.Fatalf("NormalizeObservedURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNetworkURLCollectorDedupesAndCaps(t *testing.T) {
	c := NewNetworkURLCollector(2)
	c.Add("http://example.com/a#one")
	c.Add("http://example.com/a#two")
	c.Add("data:text/html,noise")
	c.Add("https://example.com/b")
	c.Add("https://example.com/c")
	want := []string{"http://example.com/a", "https://example.com/b"}
	if got := c.URLs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("URLs() = %v, want %v", got, want)
	}
}

func TestNetworkURLCollectorDefaultsAndCopy(t *testing.T) {
	c := NewNetworkURLCollector(0)
	if c.max != DefaultMaxNetworkURLs {
		t.Fatalf("default cap = %d, want %d", c.max, DefaultMaxNetworkURLs)
	}
	c.Add("https://example.com/a")
	got := c.URLs()
	got[0] = "mutated"
	if c.URLs()[0] != "https://example.com/a" {
		t.Fatal("URLs() must return a copy")
	}
	var nilCollector *NetworkURLCollector
	nilCollector.Add("https://example.com/a")
	if nilCollector.URLs() != nil {
		t.Fatal("nil collector must stay inert")
	}
}
