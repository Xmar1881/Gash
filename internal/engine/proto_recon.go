// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/engine/proto_recon.go
// What: Engine carrier for the protocol-level recon units (TLS, DNS, TCP
// banner, SSH, DB) that now live behind the detector port.
// Why: The engine keeps exactly the responsibilities the port gives it: decide
// which units the operator asked for, build the brokered environment (scope
// decision, timeout, target lists, one shared concurrency/rate limiter, the
// phase's handshake memo), then wire findings, counters, and the audit trail
// into the report. The observation logic itself lives in internal/proto.

package engine

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/proto"
	"golang.org/x/time/rate"
)

// infraLimiter adapts the engine's bounded worker queue to the port.
// What: One semaphore plus the optional infra rate limiter for a phase.
// Why: All protocol units of a phase must share a single budget; a per-unit
// limiter would multiply the effective concurrency.
type infraLimiter struct {
	sem     chan struct{}
	limiter *rate.Limiter
}

// Acquire takes one slot, honouring scan cancellation.
func (l *infraLimiter) Acquire(ctx context.Context) bool {
	return acquireContextSlot(ctx, l.sem)
}

// Release returns one slot.
func (l *infraLimiter) Release() { <-l.sem }

// Wait blocks on the configured rate limit (always true when unset).
func (l *infraLimiter) Wait(ctx context.Context) bool {
	if l.limiter == nil {
		return true
	}
	return l.limiter.Wait(ctx) == nil
}

// newInfraLimiter builds the phase's shared limiter from the engine config.
// What: Parallelism plus the optional infra rate; nil when the phase dispatches
// no goroutines.
// Why: These are the exact limits the pre-port engine applied to the same work.
func (e *Engine) newInfraLimiter() *infraLimiter {
	parallelism := e.cfg.InfraParallelism
	if parallelism <= 0 {
		parallelism = 4
	}
	var limiter *rate.Limiter
	if e.cfg.InfraRatePerSecond > 0 {
		burst := parallelism
		if burst < 1 {
			burst = 1
		}
		limiter = rate.NewLimiter(rate.Limit(e.cfg.InfraRatePerSecond), burst)
	}
	return &infraLimiter{sem: make(chan struct{}, parallelism), limiter: limiter}
}

// parseTargetHost parses the scan target into host and scheme.
// What: Lowercased hostname plus scheme, or ok=false.
// Why: Every protocol unit needs the same normalization; the engine validates
// the target once here instead of per unit.
func parseTargetHost(target string) (*url.URL, string, bool) {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || u == nil {
		return nil, "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, "", false
	}
	return u, host, true
}

// protoEnv builds the brokered environment for the protocol units.
// What: Scope decision, timeout, target lists, shared limiter, and the phase's
// handshake memo.
// Why: The units may dial hosts directly, so everything they are allowed to
// know about policy comes from here and nowhere else.
func (e *Engine) protoEnv(target string, tlsObs *proto.TLSResult, timeout time.Duration) *detector.Env {
	policy := e.detectorPolicy()
	env := &detector.Env{Target: target, Flags: policy.Flags}
	u, host, ok := parseTargetHost(target)
	if !ok {
		return env
	}
	env.Infra = detector.Infra{
		Timeout:    timeout,
		Allow:      e.protoAllow(u),
		Limiter:    e.newInfraLimiter(),
		Targets:    func(servicePort string) []string { return e.infraTargets(host, servicePort) },
		Hosts:      func() []string { return e.infraHosts(host) },
		DBPorts:    func() []int { return proto.DBPortsNormalized(e.cfg.DBPorts, e.cfg.MaxInfraPorts) },
		TCPBanners: e.cfg.TCPBanners,
		// The deep-audit branch is entered only when the operator asked for it;
		// the unit itself never decides that from a profile.
		TLSAuditDeep:   e.cfg.TLSAuditDeep,
		TLSObservation: tlsObs,
	}
	return env
}

// runProtoRecon DNS/TLS/TCP protokol kontrollerini koşar (P2.1).
// Faz 2 sarmalayıcısıdır: TLS gözlemi dışa taşınmaz (eski imza korunur).
func (e *Engine) runProtoRecon(ctx context.Context, target string) ([]*finding.Finding, []plugin.SkippedPlugin) {
	findings, skipped, _ := e.runProtoReconTLS(ctx, target)
	return findings, skipped
}

// runProtoReconTLS runs the passive protocol units and returns the TLS
// handshake observation for the deep-audit unit (no second dial).
// What: One env, one unit list, uniform aggregation.
// Why: Profile gating, the skip wording, and the finding/counter wiring must be
// identical for every unit, which is exactly what the port provides.
func (e *Engine) runProtoReconTLS(ctx context.Context, target string) ([]*finding.Finding, []plugin.SkippedPlugin, *proto.TLSResult) {
	if _, _, ok := parseTargetHost(target); !ok {
		return nil, nil, nil
	}
	// Legacy timeout for the passive handshake/read units.
	env := e.protoEnv(target, nil, 10*time.Second)
	var (
		out     []*finding.Finding
		skipped []plugin.SkippedPlugin
		tlsObs  *proto.TLSResult
	)
	passive := []string{proto.PluginIDTLSCert, proto.PluginIDDNS}
	// TCP banner is only entered when the operator named targets; an empty list
	// means the unit does not exist for this scan.
	units := passive
	if len(e.cfg.TCPBanners) > 0 {
		units = append(append([]string{}, passive...), proto.PluginIDTCPBanner)
	}
	for _, id := range units {
		run := e.runDetector(ctx, env, id)
		if !run.Ran {
			if run.Reason != "" {
				skipped = append(skipped, plugin.SkippedPlugin{PluginID: id, Reason: run.Reason})
			}
			continue
		}
		out = append(out, run.Result.Findings...)
		skipped = append(skipped, run.Result.Skips...)
		if obs, ok := run.Result.Carry.(*proto.TLSResult); ok && obs != nil {
			tlsObs = obs
		}
	}
	return out, skipped, tlsObs
}

// runInfraRecon altyapı kontrollerini koşar (eski imza sarmalayıcısı).
func (e *Engine) runInfraRecon(ctx context.Context, target string) ([]*finding.Finding, []plugin.SkippedPlugin, map[string]int) {
	return e.runInfraReconTLS(ctx, target, nil)
}

// runInfraReconTLS altyapı kontrollerini koşar (Faz 0 MVP + Faz 1/2 derin
// denetim). tlsObs, runProtoReconTLS'ten gelen TLS el sıkışma gözlemidir; derin
// sertifika/zincir bulguları bu gözlemden ek dial açmadan türetilir (nil ise
// derin TLS dalı tek bir yerel CheckTLS ile tazeler).
// What: Bayrak tablosu (operatör hangi birimi istedi), tek ortam, tek bütçe;
// birimler kendi kapı/skip/kanıt disiplinlerini taşır.
// Why: Altyapı yüzeyi plugin HTTP hattının dışındadır; her kapı denetim izli
// skip üretir (sessiz drop yok) ve hiçbir gözlem yıkıcı işlem içermez.
func (e *Engine) runInfraReconTLS(ctx context.Context, target string, tlsObs *proto.TLSResult) ([]*finding.Finding, []plugin.SkippedPlugin, map[string]int) {
	stats := map[string]int{
		"ssh_checks": 0, "ssh_handshake_checks": 0,
		"db_ports_scanned": 0, "db_open_ports": 0, "db_unauth_checks": 0,
		"tls_deep_checks": 0,
	}
	if !e.cfg.SSHAudit && !e.cfg.DBPortScan && !e.cfg.TLSAuditDeep && !e.cfg.SSHHandshakeAudit && !e.cfg.DBUnauth {
		return nil, nil, stats
	}
	if _, _, ok := parseTargetHost(target); !ok {
		return nil, nil, stats
	}
	timeout := e.cfg.InfraTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	env := e.protoEnv(target, tlsObs, timeout)
	// The operator's flags decide which units exist for this scan; the port
	// decides whether each may run (profile gate plus --active).
	units := []struct {
		enabled bool
		id      string
	}{
		{e.cfg.SSHAudit, proto.PluginIDSSHBanner},
		{e.cfg.SSHHandshakeAudit, proto.PluginIDSSHHandshake},
		{e.cfg.DBPortScan, proto.PluginIDDBPorts},
		{e.cfg.DBUnauth, proto.PluginIDDBUnauth},
		{e.cfg.TLSAuditDeep, proto.PluginIDTLSDeep},
	}
	var (
		out     []*finding.Finding
		skipped []plugin.SkippedPlugin
	)
	for _, unit := range units {
		if !unit.enabled {
			continue
		}
		run := e.runDetector(ctx, env, unit.id)
		if !run.Ran {
			if run.Reason != "" {
				skipped = append(skipped, plugin.SkippedPlugin{PluginID: unit.id, Reason: run.Reason})
			}
			continue
		}
		out = append(out, run.Result.Findings...)
		skipped = append(skipped, run.Result.Skips...)
		for k, v := range run.Result.Stats {
			stats[k] = v
		}
	}
	return out, skipped, stats
}
