// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oob

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDisabledPollErrors(t *testing.T) {
	c := NewClient(Config{})
	if c.Enabled() {
		t.Fatal("boş server kapalı olmalı")
	}
	if _, err := c.Poll(context.Background(), "s", ""); err == nil {
		t.Fatal("kapalı client hata vermeli")
	}
}

func TestPollMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]Interaction{{CorrelationID: "c_abc", Namespace: "scan_x"}})
	}))
	defer srv.Close()
	c := NewClient(Config{ServerURL: srv.URL})
	inters, err := c.Poll(context.Background(), "scan_x", "")
	if err != nil {
		t.Fatal(err)
	}
	if !Match(inters, "c_abc", "scan_x") {
		t.Fatal("eşleşme bulunmalı")
	}
	if Match(inters, "c_abc", "başka") {
		t.Fatal("namespace dışı eşleşmemeli")
	}
}

func TestIDsUnique(t *testing.T) {
	a, _ := NewCorrelationID()
	b, _ := NewCorrelationID()
	if a == b {
		t.Fatal("corr id benzersiz olmalı")
	}
}
