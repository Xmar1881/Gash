// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package smuggle

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// mockConfig ham-TCP mock sunucu davranışıdır.
type mockConfig struct {
	vulnerable bool // CL/TE tutarsızlığı simülasyonu (desync)
	delay      time.Duration
	dials      *int32
}

// startMock localhost ham-TCP mock sunucu başlatır (dış trafik YOK).
// vulnerable=true: çift CL+TE'li ilk istekte kuyruk zehirlenir → takip
// yanıtı gecikmeli + farklı statü/gövde (TP). false: her isteğe hızlı aynı
// yanıt (TN). dials soket sayacıdır (scope kanıtı).
func startMock(t *testing.T, cfg mockConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if cfg.dials != nil {
				atomic.AddInt32(cfg.dials, 1)
			}
			go handleMockConn(c, cfg)
		}
	}()
	return "http://" + ln.Addr().String() + "/"
}

// handleMockConn bağlantı başına en fazla 2 istek yanıtlar (keep-alive).
func handleMockConn(conn net.Conn, cfg mockConfig) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	armed := false
	for i := 0; i < 2; i++ {
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		headers, ok := readMockHeaders(br)
		if !ok {
			return
		}
		slurpMockBody(conn, br, headers)
		dual := hasCL(headers) && hasChunkedTE(headers)
		status, body := 200, "OK-clean"
		if cfg.vulnerable && i == 0 && dual {
			status, body, armed = 200, "OK-first", true
		} else if cfg.vulnerable && armed && i == 1 {
			time.Sleep(cfg.delay)
			status, body = 400, "desync-queued"
		}
		resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\n\r\n%s",
			status, statusText(status), len(body), body)
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		if _, werr := io.WriteString(conn, resp); werr != nil {
			return
		}
	}
}

func statusText(code int) string {
	if code == 200 {
		return "OK"
	}
	return "Bad Request"
}

// readMockHeaders istek satırı + başlıkları okur (küçük harf anahtar).
func readMockHeaders(br *bufio.Reader) (map[string]string, bool) {
	if _, err := br.ReadString('\n'); err != nil {
		return nil, false
	}
	out := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, false
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return out, true
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:idx]))
			v := strings.TrimSpace(line[idx+1:])
			if prev, dup := out[k]; dup {
				out[k] = prev + ", " + v
			} else {
				out[k] = v
			}
		}
	}
}

// slurpMockBody gövdeyi tüketir (CL kadar veya kısa grace).
func slurpMockBody(conn net.Conn, br *bufio.Reader, h map[string]string) {
	if _, te := h["transfer-encoding"]; te {
		_ = conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
		_, _ = io.CopyN(io.Discard, br, 4096)
		return
	}
	if cl := atoi(h["content-length"]); cl > 0 {
		if cl > 8192 {
			cl = 8192
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.CopyN(io.Discard, br, int64(cl))
	}
}

func hasCL(h map[string]string) bool { return strings.TrimSpace(h["content-length"]) != "" }

func hasChunkedTE(h map[string]string) bool {
	te, ok := h["transfer-encoding"]
	if !ok {
		return false
	}
	for _, tok := range strings.Split(strings.ToLower(te), ",") {
		if strings.TrimSpace(tok) == "chunked" {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(strings.Split(s, ",")[0]))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func allowAll(host string) bool { return true }

func denyAll(host string) bool { return false }

func activeAggressive() Options {
	return Options{Allow: allowAll, Active: true, Aggressive: true}
}

// TestSmuggleVulnerableTP smuggle-açıklı mock'ta firm bulgu bekler.
func TestSmuggleVulnerableTP(t *testing.T) {
	var dials int32
	target := startMock(t, mockConfig{vulnerable: true, delay: 1000 * time.Millisecond, dials: &dials})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Scan(ctx, target, activeAggressive())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Skipped != "" {
		t.Fatalf("skip beklenmez (got %q)", res.Skipped)
	}
	if res.Finding == nil || res.Evidence == nil {
		t.Fatalf("bulgu beklenir (requests=%d detail=%v)", res.Requests, res.Detail)
	}
	f := res.Finding
	if f.RuleID != RuleID || f.CWE != CWE {
		t.Fatalf("yanlış kimlik %s/%s (GASH-033/CWE-444 beklenir)", f.RuleID, f.CWE)
	}
	if f.OracleName != OracleName {
		t.Fatalf("yanlış oracle %q", f.OracleName)
	}
	if f.Confidence == plugin.ConfidenceConfirmed {
		t.Fatalf("smuggling-differential confirmed ÜRETEMEZ (tavan firm)")
	}
	if f.Confidence != plugin.ConfidenceFirm {
		t.Fatalf("çift kanıt → firm beklenir (got %q)", f.Confidence)
	}
	if res.Requests > MaxProbes {
		t.Fatalf("hacim tavanı aşıldı: %d > %d", res.Requests, MaxProbes)
	}
	if atomic.LoadInt32(&dials) == 0 {
		t.Fatalf("prob soket açmalıydı (lab localhost)")
	}
}

// TestSmuggleConsistentTN tutarlı sunucuda bulgu YOK.
func TestSmuggleConsistentTN(t *testing.T) {
	target := startMock(t, mockConfig{vulnerable: false})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Scan(ctx, target, activeAggressive())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Skipped != "" {
		t.Fatalf("skip beklenmez (got %q)", res.Skipped)
	}
	if res.Finding != nil || res.Evidence != nil {
		t.Fatalf("tutarlı sunucuda bulgu YOK (got %+v)", res.Finding)
	}
	if res.Requests > MaxProbes {
		t.Fatalf("hacim tavanı aşıldı: %d", res.Requests)
	}
}

// TestSmuggleScopeViolationNoSocket kapsam-dışı → ErrScopeViolation, soket YOK.
func TestSmuggleScopeViolationNoSocket(t *testing.T) {
	var dials int32
	target := startMock(t, mockConfig{vulnerable: true, delay: time.Second, dials: &dials})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Scan(ctx, target, Options{Allow: denyAll, Active: true, Aggressive: true})
	if !errors.Is(err, plugin.ErrScopeViolation) {
		t.Fatalf("ErrScopeViolation beklenir (got %v)", err)
	}
	if n := atomic.LoadInt32(&dials); n != 0 {
		t.Fatalf("kapsam-dışı soket AÇILMAMALI (dials=%d)", n)
	}
}

// TestSmuggleNilAllowFailClosed kapsam kararı yoksa fail-closed, soket YOK.
func TestSmuggleNilAllowFailClosed(t *testing.T) {
	var dials int32
	target := startMock(t, mockConfig{vulnerable: true, delay: time.Second, dials: &dials})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Scan(ctx, target, Options{Active: true, Aggressive: true})
	if !errors.Is(err, plugin.ErrScopeViolation) {
		t.Fatalf("nil Allow → ErrScopeViolation beklenir (got %v)", err)
	}
	if n := atomic.LoadInt32(&dials); n != 0 {
		t.Fatalf("fail-closed: soket AÇILMAMALI (dials=%d)", n)
	}
}

// TestSmuggleGateSkips kapı dışı (safe/standard) → skip, soket YOK.
func TestSmuggleGateSkips(t *testing.T) {
	var dials int32
	target := startMock(t, mockConfig{vulnerable: true, delay: time.Second, dials: &dials})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, opts := range []Options{
		{Allow: allowAll, Active: false, Aggressive: false}, // safe
		{Allow: allowAll, Active: true, Aggressive: false},  // standard/active ama agresif yok
		{Allow: allowAll, Active: false, Aggressive: true},
	} {
		res, err := Scan(ctx, target, opts)
		if err != nil {
			t.Fatalf("gate skip hata üretmemeli (got %v)", err)
		}
		if res.Skipped == "" {
			t.Fatalf("kapı dışı → skip beklenir (%+v)", opts)
		}
		if res.Finding != nil {
			t.Fatalf("kapı dışı → bulgu YOK")
		}
	}
	if n := atomic.LoadInt32(&dials); n != 0 {
		t.Fatalf("skip yolunda soket AÇILMAMALI (dials=%d)", n)
	}
}

// TestSmuggleExternalRefused dış hedefe ham soket YOK (dokümantasyon IP'si,
// dial öncesi ret; ağa ÇIKILMAZ).
func TestSmuggleExternalRefused(t *testing.T) {
	var dials int32
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := Scan(ctx, "http://203.0.113.7/", Options{
		Allow: allowAll, Active: true, Aggressive: true,
		DialHook: func() { atomic.AddInt32(&dials, 1) },
	})
	if err != nil {
		t.Fatalf("lab-only ret hata üretmemeli (got %v)", err)
	}
	if res.Skipped == "" {
		t.Fatalf("dış hedef → skip beklenir")
	}
	if res.Finding != nil {
		t.Fatalf("dış hedef → bulgu YOK")
	}
	if n := atomic.LoadInt32(&dials); n != 0 {
		t.Fatalf("dış hedefe ham soket YOK (dials=%d)", n)
	}
}

// TestSmuggleSingleChannelRejects tek-kanal sinyal bulgu ÜRETMEZ.
func TestSmuggleSingleChannelRejects(t *testing.T) {
	fast := pairOutcome{kind: "control",
		second: respSummary{status: 200, body: []byte("OK-clean")}}
	// Yalnızca statü farkı, gecikme YOK → reject.
	onlyDiff := pairOutcome{kind: KindCLTE,
		second: respSummary{status: 400, body: []byte("other")}}
	if ev := decide(fast, []pairOutcome{onlyDiff}); ev != nil {
		t.Fatalf("tek-kanal differential bulgu üretmemeli")
	}
	// Bozuk kontrol → reject.
	broken := pairOutcome{kind: "control", second: respSummary{timeout: true}}
	dual := pairOutcome{kind: KindCLTE,
		second: respSummary{status: 400, body: []byte("other"), rtt: 2 * time.Second}}
	if ev := decide(broken, []pairOutcome{dual}); ev != nil {
		t.Fatalf("bozuk kontrol bulgu üretmemeli")
	}
}

// TestSmuggleRuleIdentity kimlik sabitlerini kilitler (çakışma yok).
func TestSmuggleRuleIdentity(t *testing.T) {
	if RuleID != "GASH-033" || CWE != "CWE-444" {
		t.Fatalf("kimlik kaydı: %s/%s", RuleID, CWE)
	}
	if OracleName != "smuggling-differential" {
		t.Fatalf("oracle adı: %q", OracleName)
	}
	if MaxProbes > 10 {
		t.Fatalf("hacim tavanı: %d", MaxProbes)
	}
}
