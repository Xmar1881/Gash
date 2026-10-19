// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"io"
	"strings"
	"testing"
)

// TestScanBrowserVerifyRequiresActive: tarayıcı doğrulaması aktif probdur;
// --active olmadan scan erken hata vermeli (OOB kapısıyla aynı disiplin).
func TestScanBrowserVerifyRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--browser-verify"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--browser-verify tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--browser-verify") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --browser-verify + --active taşımalı: %v", err)
	}
}

// TestScanOOBServerRequiresActive: mevcut OOB kapısı pini (regresyon ağı).
func TestScanOOBServerRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--oob-server", "http://127.0.0.1:9"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--oob-server tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--oob-server") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --oob-server + --active taşımalı: %v", err)
	}
}

// TestScanSSHAuditRequiresActive: SSH banner probu aktif probdur.
func TestScanSSHAuditRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--ssh-audit"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--ssh-audit tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--ssh-audit") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --ssh-audit + --active taşımalı: %v", err)
	}
}

// TestScanDBPortScanRequiresActive: DB port probu aktif probdur.
func TestScanDBPortScanRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--db-port-scan"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--db-port-scan tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--db-port-scan") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --db-port-scan + --active taşımalı: %v", err)
	}
}

// TestScanInfraTargetValidation: --infra-target host:port biçimi doğrulanır.
func TestScanInfraTargetValidation(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--infra-target", "hostsuz-port"})
	err := root.Execute()
	if err == nil {
		t.Fatal("portsuz --infra-target hata vermeli")
	}
	if !strings.Contains(err.Error(), "--infra-target") {
		t.Fatalf("gerekçe --infra-target taşımalı: %v", err)
	}
}

// TestScanDBPortsValidation: bozuk --db-ports listesi erken hata verir.
func TestScanDBPortsValidation(t *testing.T) {
	for _, bad := range []string{"70000", "abc", "0"} {
		root := newRoot()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--db-ports", bad})
		err := root.Execute()
		if err == nil {
			t.Fatalf("--db-ports %q hata vermeli", bad)
		}
		if !strings.Contains(err.Error(), "--db-ports") {
			t.Fatalf("gerekçe --db-ports taşımalı: %v", err)
		}
	}
}

// TestParseDBPorts: ayrıştırıcı birim davranışı (boşluk, yineleme, sınır).
func TestParseDBPorts(t *testing.T) {
	got, err := parseDBPorts(" 3306, 5432 ,3306,")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 3306 || got[1] != 5432 {
		t.Fatalf("liste: %v", got)
	}
	empty, err := parseDBPorts("")
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("boş liste: %v", empty)
	}
}

// TestScanInfraTimeoutValidation: bozuk süre erken hata verir.
func TestScanInfraTimeoutValidation(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--infra-timeout", "bes-saniye"})
	err := root.Execute()
	if err == nil {
		t.Fatal("bozuk --infra-timeout hata vermeli")
	}
	if !strings.Contains(err.Error(), "--infra-timeout") {
		t.Fatalf("gerekçe --infra-timeout taşımalı: %v", err)
	}
}

// TestScanSSHHandshakeAuditRequiresActive: KEXINIT probu aktif probdur (Faz 1).
func TestScanSSHHandshakeAuditRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--ssh-handshake-audit"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--ssh-handshake-audit tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--ssh-handshake-audit") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --ssh-handshake-audit + --active taşımalı: %v", err)
	}
}

// TestScanDBUnauthRequiresActive: unauth probu tek istek gönderir (Faz 1).
func TestScanDBUnauthRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--db-unauth"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--db-unauth tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--db-unauth") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --db-unauth + --active taşımalı: %v", err)
	}
}

// TestScanLoginURLRequiresActive: oturum kurulumu POST gönderir; --active şart.
func TestScanLoginURLRequiresActive(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--login-url", "http://127.0.0.1:1/login", "--login-user", "u", "--login-pass", "p"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--login-url tek başına hata vermeli")
	}
	if !strings.Contains(err.Error(), "--login-url") || !strings.Contains(err.Error(), "--active") {
		t.Fatalf("gerekçe --login-url + --active taşımalı: %v", err)
	}
}

// TestScanLoginFlagsRequireLoginURL: alt bayraklar tek başına anlamsızdır.
func TestScanLoginFlagsRequireLoginURL(t *testing.T) {
	for _, args := range [][]string{
		{"--login-user", "u"},
		{"--login-pass", "p"},
		{"--login-pass-env", "GASH_TEST_LOGIN_PASS"},
		{"--login-user-field", "user"},
		{"--login-verify-url", "http://127.0.0.1:1/panel"},
	} {
		full := append([]string{"scan", "--target", "http://127.0.0.1:1", "--active"}, args...)
		root := newRoot()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs(full)
		err := root.Execute()
		if err == nil {
			t.Fatalf("%v: --login-url olmadan hata vermeli", args)
		}
		if !strings.Contains(err.Error(), "--login-url") {
			t.Fatalf("%v: gerekçe --login-url taşımalı: %v", args, err)
		}
	}
}

// TestScanLoginRequiresUser: tek kimlik seti için kullanıcı zorunludur.
func TestScanLoginRequiresUser(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--login-url", "http://127.0.0.1:1/login", "--login-pass", "p"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--login-user olmadan hata vermeli")
	}
	if !strings.Contains(err.Error(), "--login-user") {
		t.Fatalf("gerekçe --login-user taşımalı: %v", err)
	}
}

// TestScanLoginRequiresPass: parola (veya env) zorunludur; deneme YOK.
func TestScanLoginRequiresPass(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--login-url", "http://127.0.0.1:1/login", "--login-user", "u"})
	err := root.Execute()
	if err == nil {
		t.Fatal("parolasız login hata vermeli")
	}
	if !strings.Contains(err.Error(), "--login-pass") {
		t.Fatalf("gerekçe --login-pass taşımalı: %v", err)
	}
}

// TestScanLoginPassConflict: --login-pass ve --login-pass-env birlikte olamaz.
func TestScanLoginPassConflict(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--login-url", "http://127.0.0.1:1/login", "--login-user", "u", "--login-pass", "p", "--login-pass-env", "GASH_TEST_LOGIN_PASS"})
	err := root.Execute()
	if err == nil {
		t.Fatal("çift parola kaynağı hata vermeli")
	}
	if !strings.Contains(err.Error(), "birlikte kullanılamaz") {
		t.Fatalf("gerekçe birleşme yasağı taşımalı: %v", err)
	}
}

// TestScanLoginPassEnvMissing: tanımsız/boş env değişkeni erken hata verir.
func TestScanLoginPassEnvMissing(t *testing.T) {
	t.Setenv("GASH_TEST_LOGIN_PASS_MISSING", "")
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--login-url", "http://127.0.0.1:1/login", "--login-user", "u", "--login-pass-env", "GASH_TEST_LOGIN_PASS_MISSING"})
	err := root.Execute()
	if err == nil {
		t.Fatal("boş env değişkeni hata vermeli")
	}
	if !strings.Contains(err.Error(), "GASH_TEST_LOGIN_PASS_MISSING") {
		t.Fatalf("gerekçe env değişken adını taşımalı: %v", err)
	}
}

// TestScanLoginScopePreflight: kapsam-dışı login URL'i ağ trafiği başlamadan
// fail-closed reddedilir.
func TestScanLoginScopePreflight(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--scope", "203.0.113.0/24", "--login-url", "http://10.1.2.3/login", "--login-user", "u", "--login-pass", "p"})
	err := root.Execute()
	if err == nil {
		t.Fatal("kapsam-dışı --login-url hata vermeli")
	}
	if !strings.Contains(err.Error(), "--login-url") || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("gerekçe --login-url + scope taşımalı: %v", err)
	}
}

// TestScanLoginURLShapeValidation: http(s) dışı login URL'i erken reddedilir.
func TestScanLoginURLShapeValidation(t *testing.T) {
	root := newRoot()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"scan", "--target", "http://127.0.0.1:1", "--active", "--login-url", "ftp://x.example/login", "--login-user", "u", "--login-pass", "p"})
	err := root.Execute()
	if err == nil {
		t.Fatal("ftp login URL'i hata vermeli")
	}
	if !strings.Contains(err.Error(), "--login-url") {
		t.Fatalf("gerekçe --login-url taşımalı: %v", err)
	}
}
