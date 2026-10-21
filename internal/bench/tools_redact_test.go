// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"reflect"
	"testing"
)

func TestRedactedCommandHidesCredentials(t *testing.T) {
	args := []string{"scan", "--auth-header", "Cookie: PHPSESSID=secret", "--auth-user-a", "a", "--auth-user-b", "b", "-H", "Authorization: Bearer token"}
	got := redactedCommand("gash", args)
	want := []string{"gash", "scan", "--auth-header", "<redacted>", "--auth-user-a", "<redacted>", "--auth-user-b", "<redacted>", "-H", "<redacted>"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("redacted command = %v, want %v", got, want)
	}
	if args[2] != "Cookie: PHPSESSID=secret" || args[8] != "Authorization: Bearer token" {
		t.Fatal("redaction mutated the executable arguments")
	}
	if redactAuth("") != "" || redactAuth("Cookie: x") != "<redacted>" {
		t.Fatal("auth redaction did not hide a non-empty value")
	}
}
