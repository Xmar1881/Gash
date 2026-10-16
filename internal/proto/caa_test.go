// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/miekg/dns"
)

// startLoopbackCAAServer yalnızca loopback'te yanıt veren sahte DNS sunucusudur.
// What: healthy.test → sağlıklı CAA; empty.test → NODATA; diğer → NXDOMAIN.
// Why: Dış DNS'e gerçek sorgu testte YOK; wire ayrıştırma mock resolver ile kanıtlanır.
func startLoopbackCAAServer(t *testing.T) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		if len(req.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := req.Question[0]
		name := strings.ToLower(q.Name)
		if q.Qtype != dns.TypeCAA {
			_ = w.WriteMsg(m)
			return
		}
		switch name {
		case "healthy.test.":
			m.Answer = []dns.RR{&dns.CAA{
				Hdr:   dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60},
				Flag:  0,
				Tag:   "issue",
				Value: "letsencrypt.org",
			}}
		case "empty.test.":
			// NODATA: NOERROR + yanıtsız → missing bulgusu.
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// startBlackholeUDP gelen paketleri yanıtsız yutan loopback sunucusudur (timeout kanıtı).
func startBlackholeUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestCheckCAAMissing(t *testing.T) {
	o := Options{Allow: allowAll, LookupCAA: func(string) ([]CAARecord, error) { return nil, nil }}
	r, err := CheckCAA(context.Background(), "ornek.test", o)
	if err != nil {
		t.Fatalf("caa: %v", err)
	}
	found := CAAFindings("https://ornek.test/", r)
	if len(found) != 1 {
		t.Fatalf("1 missing bulgusu bekleniyordu: %+v", found)
	}
	f := found[0]
	if f.RuleID != "GASH-027" || f.CWE != "CWE-295" {
		t.Fatalf("kural: %s/%s", f.RuleID, f.CWE)
	}
	if f.Confidence != plugin.ConfidenceFirm {
		t.Fatalf("tavan firm olmalı: %s", f.Confidence)
	}
	if f.Severity != plugin.SeverityMedium {
		t.Fatalf("şiddet medium: %s", f.Severity)
	}
	if f.PluginID != "proto-dns-caa" || f.OracleName != "dns" {
		t.Fatalf("kimlik: %s/%s", f.PluginID, f.OracleName)
	}
	if f.Evidence["signal"] != "missing-caa" {
		t.Fatalf("sinyal: %+v", f.Evidence)
	}
}

func TestCheckCAAHealthy(t *testing.T) {
	o := Options{Allow: allowAll, LookupCAA: func(string) ([]CAARecord, error) {
		return []CAARecord{
			{Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
			{Flag: 0, Tag: "issuewild", Value: ";"},
			{Flag: 0, Tag: "iodef", Value: "mailto:security@example.com"},
		}, nil
	}}
	r, err := CheckCAA(context.Background(), "ornek.test", o)
	if err != nil {
		t.Fatalf("caa: %v", err)
	}
	if got := CAAFindings("https://ornek.test/", r); len(got) != 0 {
		t.Fatalf("sağlıklı CAA bulgusuz olmalı: %+v", got)
	}
}

func TestCheckCAAMalformed(t *testing.T) {
	cases := map[string][]CAARecord{
		"empty-tag":   {{Flag: 0, Tag: "", Value: "letsencrypt.org"}},
		"bad-tag":     {{Flag: 0, Tag: "bad tag!", Value: "letsencrypt.org"}},
		"empty-value": {{Flag: 0, Tag: "issue", Value: "  "}},
		"bad-iodef":   {{Flag: 0, Tag: "iodef", Value: "not-a-url"}},
	}
	for name, recs := range cases {
		o := Options{Allow: allowAll, LookupCAA: func(string) ([]CAARecord, error) { return recs, nil }}
		r, err := CheckCAA(context.Background(), "ornek.test", o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		found := CAAFindings("https://ornek.test/", r)
		if len(found) != 1 {
			t.Fatalf("%s: 1 malformed bulgusu bekleniyordu: %+v", name, found)
		}
		f := found[0]
		if f.RuleID != "GASH-027" || f.Confidence != plugin.ConfidenceFirm {
			t.Fatalf("%s: kural/güven: %+v", name, f)
		}
		if f.Evidence["signal"] != "malformed-caa" {
			t.Fatalf("%s: sinyal: %+v", name, f.Evidence)
		}
	}
}

func TestCheckCAALoopbackWire(t *testing.T) {
	server := startLoopbackCAAServer(t)
	o := Options{Allow: allowAll, CAAServer: server, Timeout: 2 * time.Second}
	// Sağlıklı wire yanıt → bulgusuz.
	healthy, err := CheckCAA(context.Background(), "healthy.test", o)
	if err != nil {
		t.Fatalf("wire sağlıklı: %v", err)
	}
	if len(healthy.Records) != 1 || healthy.Records[0].Tag != "issue" {
		t.Fatalf("wire kayıt: %+v", healthy)
	}
	if got := CAAFindings("https://healthy.test/", healthy); len(got) != 0 {
		t.Fatalf("wire sağlıklı bulgusuz olmalı: %+v", got)
	}
	// NODATA → missing bulgusu.
	empty, err := CheckCAA(context.Background(), "empty.test", o)
	if err != nil {
		t.Fatalf("wire nodata: %v", err)
	}
	found := CAAFindings("https://empty.test/", empty)
	if len(found) != 1 || found[0].Evidence["signal"] != "missing-caa" {
		t.Fatalf("wire missing: %+v", found)
	}
	// NXDOMAIN → hata, bulgu yok (FP üretme).
	if _, err := CheckCAA(context.Background(), "yok.test", o); err == nil {
		t.Fatal("NXDOMAIN sessiz hata olmalı")
	}
}

func TestCheckCAATimeoutSilent(t *testing.T) {
	server := startBlackholeUDP(t)
	o := Options{Allow: allowAll, CAAServer: server, Timeout: 300 * time.Millisecond}
	start := time.Now()
	_, err := CheckCAA(context.Background(), "ornek.test", o)
	if err == nil {
		t.Fatal("timeout hata dönmeli (sessiz, bulgusuz)")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout tavanı aşılmamalı: %v", time.Since(start))
	}
}

func TestCheckCAAScopeAndIP(t *testing.T) {
	deny := Options{Allow: func(string) bool { return false }}
	if _, err := CheckCAA(context.Background(), "ornek.test", deny); err == nil {
		t.Fatal("kapsam-dışı CAA reddedilmeli")
	}
	if _, err := CheckCAA(context.Background(), "  ", Options{Allow: allowAll}); err == nil {
		t.Fatal("boş host reddedilmeli")
	}
	ipRes, err := CheckCAA(context.Background(), "127.0.0.1", Options{Allow: allowAll})
	if err != nil {
		t.Fatalf("ip: %v", err)
	}
	if got := CAAFindings("http://127.0.0.1/", ipRes); len(got) != 0 {
		t.Fatalf("IP literal bulgusuz: %+v", got)
	}
	if got := CAAFindings("https://ornek.test/", nil); len(got) != 0 {
		t.Fatalf("nil sonuç bulgusuz: %+v", got)
	}
}

func TestCAATimeoutCap(t *testing.T) {
	if got := caaTimeout(Options{Timeout: 10 * time.Second}); got != 5*time.Second {
		t.Fatalf("tavan 5s olmalı: %v", got)
	}
	if got := caaTimeout(Options{Timeout: 300 * time.Millisecond}); got != 300*time.Millisecond {
		t.Fatalf("küçük timeout korunmalı: %v", got)
	}
}
