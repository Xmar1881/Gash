// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/proto/detectors.go
// What: Protocol-level recon units (TLS, DNS, TCP banner, SSH, DB) exposed
// through the engine detector port.
// Why: These observations dial hosts directly (handshake, DNS query, TCP
// connect), so they cannot live in YAML or the JS sandbox and used to be eight
// if-blocks inside internal/engine/scan_exec.go with their gates, scope checks,
// concurrency, telemetry keys, and skip wording written by hand. The port keeps
// the engine as carrier (it owns scope, the shared limiter, the timeout, the
// target lists, and forwards the audit trail) while each unit owns its identity,
// probing, findings, and counters.

package proto

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
)

const (
	// PluginIDTLSCert is the certificate/chain observation unit (GASH-024).
	PluginIDTLSCert = "proto-tls-cert"
	// PluginIDTLSDeep is the deep certificate/version audit unit (GASH-024).
	PluginIDTLSDeep = "proto-tls-deep"
	// PluginIDDNS is the DNS record plus CAA unit (GASH-025/GASH-027).
	PluginIDDNS = "proto-dns-records"
	// PluginIDTCPBanner is the TCP banner unit (GASH-026).
	PluginIDTCPBanner = "proto-tcp-banner"
	// PluginIDSSHBanner is the SSH banner plus version-advisory unit
	// (GASH-052/GASH-056).
	PluginIDSSHBanner = "proto-ssh-banner"
	// PluginIDSSHHandshake is the SSH KEXINIT algorithm unit (GASH-054).
	PluginIDSSHHandshake = "proto-ssh-handshake"
	// PluginIDDBPorts is the database port inventory unit (GASH-053).
	PluginIDDBPorts = "proto-db-ports"
	// PluginIDDBUnauth is the database unauthenticated-access unit (GASH-055).
	PluginIDDBUnauth = "proto-db-unauth"
)

const (
	// handshakeTimeout caps the TLS/DNS observations (legacy 12 s budget).
	handshakeTimeout = 12 * time.Second
	// defaultTLSPort is the port used when the target URL names none.
	defaultTLSPort = "443"
	// defaultSSHPort is the SSH service port used for infra targets.
	defaultSSHPort = "22"
	// detectorVersionProto is the version stamped on the port units.
	detectorVersionProto = "1.0"
)

// infraTarget parses the scan target and returns its lowercased host, plus the
// parsed URL. What: The shape checks every protocol unit shares.
// Why: One parser keeps the host normalization identical across units.
func infraTarget(env *detector.Env) (*url.URL, string, bool) {
	if env == nil {
		return nil, "", false
	}
	u, err := url.Parse(strings.TrimSpace(env.Target))
	if err != nil || u == nil {
		return nil, "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, "", false
	}
	return u, host, true
}

// infraOptions builds the protocol observation options from the env.
// What: Timeout and the host-level scope decision, nothing else.
// Why: The units must never invent a timeout or a scope allowance.
func infraOptions(env *detector.Env) Options {
	return Options{Timeout: env.Infra.Timeout, Allow: env.Infra.Allow}
}

// findingsOf converts protocol findings to engine findings.
// What: Shared conversion for every unit.
// Why: `ToFinding` is the only sanctioned path from a protocol observation to a
// finding; keeping it in one helper makes that auditable.
func findingsOf(in []Finding) []*finding.Finding {
	out := make([]*finding.Finding, 0, len(in))
	for _, pf := range in {
		pf := pf
		out = append(out, pf.ToFinding())
	}
	return out
}

// TLSDetector observes the certificate chain of an https target (GASH-024).
// What: One handshake, certificate/chain findings, and the observation carried
// forward so the deep unit never dials twice.
// Why: The observation is the phase's most expensive artifact; the engine memo
// exists because two units legitimately derive different findings from it.
type TLSDetector struct{}

// Spec describes the certificate observation unit.
// What: Profile gate `tls`, no activation requirement, https-only shape check.
// Why: A handshake is a read-only observation, so it stays in the safe profile.
func (TLSDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDTLSCert,
		Name:            "TLS certificate and chain observation",
		Description:     "Handshake observation of an https target: expiry, chain completeness, hostname match and protocol version facts, derived without any payload.",
		RuleID:          "GASH-024",
		CWE:             "CWE-295",
		Oracle:          "tls",
		Severity:        plugin.SeverityMedium,
		Phase:           plugin.PhaseRecon,
		Order:           110,
		Gate:            "tls",
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: detectorVersionProto,
	}
}

// Run performs one TLS observation.
// What: Nothing for a non-https target; one handshake plus findings otherwise.
// Why: A plaintext target has no certificate to observe, and the legacy
// behaviour must not dial one.
func (TLSDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	u, host, ok := infraTarget(env)
	if !ok || !strings.EqualFold(u.Scheme, "https") {
		return detector.Result{}, nil
	}
	port := u.Port()
	if port == "" {
		port = defaultTLSPort
	}
	c, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	res, err := CheckTLS(c, net.JoinHostPort(host, port), infraOptions(env))
	if err != nil || res == nil {
		return detector.Result{}, nil
	}
	return detector.Result{
		Findings: findingsOf(TLSFindings(env.Target, res)),
		Carry:    res,
	}, nil
}

// TLSDeepDetector derives deep certificate and version-acceptance findings.
// What: Reuses the phase's TLS observation when present, otherwise dials once.
// Why: The deep facts come from the same handshake; a second dial would double
// the phase's traffic for no new information.
type TLSDeepDetector struct{}

// Spec describes the deep TLS audit unit.
// What: Same profile gate as the certificate unit, no activation requirement.
// Why: Version-acceptance probing is read-only, bounded, and bounded again by
// the operator flag that decides whether the unit is entered at all.
func (TLSDeepDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDTLSDeep,
		Name:            "Deep TLS audit (versions, certificate depth)",
		Description:     "Derives weak protocol version acceptance and certificate-depth facts from the phase's handshake observation, re-dialing only when no observation exists.",
		RuleID:          "GASH-024",
		CWE:             "CWE-295",
		Oracle:          "tls",
		Severity:        plugin.SeverityMedium,
		Phase:           plugin.PhaseRecon,
		Order:           180,
		Gate:            "tls",
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: detectorVersionProto,
	}
}

// Run performs the deep audit.
// What: Target-shape and scope refusals become audit-trailed skips.
// Why: The operator asked for the deep audit explicitly, so refusing it must be
// visible in the report instead of silent.
func (TLSDeepDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	u, host, ok := infraTarget(env)
	if !ok {
		return detector.Result{}, nil
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return detector.Result{Skips: []plugin.SkippedPlugin{{
			PluginID: PluginIDTLSDeep,
			Reason:   "skipped (tls-audit-deep requires an https target)",
		}}}, nil
	}
	if env.Infra.Allow == nil || !env.Infra.Allow(host) {
		return detector.Result{Skips: []plugin.SkippedPlugin{{
			PluginID: PluginIDTLSDeep,
			Reason:   "skipped (tls-audit-deep target outside scope, no socket opened)",
		}}}, nil
	}
	port := u.Port()
	if port == "" {
		port = defaultTLSPort
	}
	addr := net.JoinHostPort(host, port)
	res := detector.Result{Stats: map[string]int{"tls_deep_checks": 0}}
	if !acquire(env, ctx) {
		return res, nil
	}
	defer release(env)
	c, cancel := context.WithTimeout(ctx, infraTimeout(env))
	defer cancel()

	obs, _ := env.Infra.TLSObservation.(*TLSResult)
	if obs == nil {
		r, err := CheckTLS(c, addr, infraOptions(env))
		if err != nil || r == nil {
			return res, nil
		}
		obs = r
	}
	deepFS := TLSDeepFindings(env.Target, obs)
	probes := 0
	var versionFS []Finding
	if audit, err := CheckTLSVersionSupport(c, addr, infraOptions(env)); err == nil && audit != nil {
		versionFS = TLSAuditFindings(env.Target, audit)
		probes = len(audit.Probes)
	}
	res.Stats["tls_deep_checks"] = probes
	res.Findings = append(findingsOf(versionFS), findingsOf(deepFS)...)
	return res, nil
}

// DNSDetector reads SPF/DMARC records and the CAA policy (GASH-025/GASH-027).
// What: Two read-only queries on one context, IP literals excluded.
// Why: An IP literal has no records to read, and both observations share the
// same scope allowance and deadline.
type DNSDetector struct{}

// Spec describes the DNS observation unit.
// What: Profile gate `dns`, no activation requirement.
// Why: DNS reads are passive and safe-profile eligible.
func (DNSDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDDNS,
		Name:            "DNS records and CAA policy",
		Description:     "Reads SPF/DMARC records and the CAA policy of the target host; no zone transfer, no dynamic update.",
		RuleID:          "GASH-025",
		CWE:             "CWE-693",
		Oracle:          "dns",
		Severity:        plugin.SeverityLow,
		Phase:           plugin.PhaseRecon,
		Order:           120,
		Gate:            "dns",
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: detectorVersionProto,
	}
}

// Run performs the DNS observations.
// What: Placement of a missing policy is a finding; a lookup error is silent.
// Why: A resolver failure must never become a false positive.
func (DNSDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	_, host, ok := infraTarget(env)
	if !ok || net.ParseIP(host) != nil {
		return detector.Result{}, nil
	}
	c, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	var out []*finding.Finding
	if res, err := CheckDNS(c, host, infraOptions(env)); err == nil && res != nil {
		out = append(out, findingsOf(DNSFindings(env.Target, res))...)
	}
	if caaRes, err := CheckCAA(c, host, infraOptions(env)); err == nil && caaRes != nil {
		out = append(out, findingsOf(CAAFindings(env.Target, caaRes))...)
	}
	return detector.Result{Findings: out}, nil
}

// TCPBannerDetector grabs operator-supplied TCP banners (GASH-026).
// What: Connect plus read, one entry per explicit target.
// Why: The unit only exists because the operator named targets; without
// --active every named target leaves an audit-trailed skip.
type TCPBannerDetector struct{}

// Spec describes the TCP banner unit.
// What: Profile gate `tcp`, `--active` required, banner-shaped skip subject.
// Why: A connect is active traffic, so the unit must never run unasked.
func (TCPBannerDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDTCPBanner,
		Name:            "TCP banner grab",
		Description:     "Connects to each operator-supplied address and reads the greeting banner; nothing is written to the socket.",
		RuleID:          "GASH-026",
		CWE:             "CWE-200",
		Oracle:          "tcp",
		Severity:        plugin.SeverityLow,
		Phase:           plugin.PhaseRecon,
		Order:           130,
		Gate:            "tcp",
		RequiresActive:  true,
		SkipSubject:     "tcp-banner",
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: detectorVersionProto,
	}
}

// Run reads the banners the operator asked for.
// What: One audit-trailed skip per address without --active, never silence.
// Why: "Sessiz drop yok" (no silent drop): a configured target that was not
// contacted must be explainable from the report alone.
func (TCPBannerDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	res := detector.Result{}
	for _, raw := range env.Infra.TCPBanners {
		addr := strings.TrimSpace(raw)
		if addr == "" {
			continue
		}
		if !env.Flags.Active {
			res.Skips = append(res.Skips, plugin.SkippedPlugin{
				PluginID: PluginIDTCPBanner,
				Reason:   "skipped (tcp-banner " + addr + " requires --active)",
			})
			continue
		}
		c, cancel := context.WithTimeout(ctx, handshakeTimeout)
		obs, err := GrabBanner(c, addr, infraOptions(env))
		cancel()
		if err != nil || obs == nil {
			continue
		}
		res.Findings = append(res.Findings, findingsOf(BannerFindings(env.Target, obs))...)
	}
	return res, nil
}

// SSHBannerDetector reads the SSH banner and maps the software version
// (GASH-052/GASH-056).
// What: Bounded concurrent banner reads with the shared limiter.
// Why: The version mapping suppresses the generic "old software" signal once a
// specific advisory fires, so both sets come from one unit.
type SSHBannerDetector struct{}

// Spec describes the SSH banner unit.
// What: Profile gate `ssh`, `--active` required.
// Why: The banner read opens a real connection, so it is active traffic.
func (SSHBannerDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDSSHBanner,
		Name:            "SSH banner and version advisories",
		Description:     "Reads the SSH banner of each infra target and maps curate software versions to advisories; no key exchange, no authentication.",
		RuleID:          "GASH-052",
		CWE:             "CWE-200",
		Oracle:          "ssh",
		Severity:        plugin.SeverityMedium,
		Phase:           plugin.PhaseRecon,
		Order:           140,
		Gate:            "ssh",
		RequiresActive:  true,
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: detectorVersionProto,
	}
}

// Run reads banners for every infra target.
// What: Scope-denied targets produce a skip and open no socket.
// Why: The infra target list can name hosts outside --scope (operator typo);
// failing closed with an audit entry is the only acceptable outcome.
func (SSHBannerDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	res := detector.Result{Stats: map[string]int{"ssh_checks": 0}}
	if env.Infra.Targets == nil {
		return res, nil
	}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		out  []*finding.Finding
		seen int
	)
	for _, addr := range env.Infra.Targets(defaultSSHPort) {
		h, p, aerr := net.SplitHostPort(addr)
		if aerr != nil {
			continue
		}
		if !allowed(env, h) {
			res.Skips = append(res.Skips, plugin.SkippedPlugin{
				PluginID: PluginIDSSHBanner,
				Reason:   "skipped (infra target " + addr + " outside scope, no socket opened)",
			})
			continue
		}
		wg.Add(1)
		go func(h, p, addr string) {
			defer wg.Done()
			if !acquire(env, ctx) {
				return
			}
			defer release(env)
			if !wait(env, ctx) {
				return
			}
			c, cancel := context.WithTimeout(ctx, infraTimeout(env))
			defer cancel()
			obs, err := CheckSSH(c, h, p, infraOptions(env))
			mu.Lock()
			defer mu.Unlock()
			seen++
			if err != nil || obs == nil {
				return
			}
			fs := SSHFindings(env.Target, obs)
			// Faz 2: sürüm→bildirim eşlemesi (GASH-056) tetiklendiğinde jenerik
			// "ssh-old-software" sinyali düşürülür; protokol 1.x bulgusu korunur.
			vfs := SSHVersionFindings(env.Target, obs.Software)
			if len(vfs) > 0 {
				kept := fs[:0]
				for _, f := range fs {
					if f.Evidence["signal"] != "ssh-old-software" {
						kept = append(kept, f)
					}
				}
				fs = kept
			}
			out = append(out, findingsOf(fs)...)
			out = append(out, findingsOf(vfs)...)
		}(h, p, addr)
	}
	wg.Wait()
	res.Stats["ssh_checks"] = seen
	res.Findings = out
	return res, nil
}

// SSHHandshakeDetector observes the KEXINIT algorithm proposal (GASH-054).
// What: One fixed client proposal, no key exchange, no authentication.
// Why: Declared algorithms prove weakness; completing a handshake would prove
// nothing more and would touch the target's auth surface.
type SSHHandshakeDetector struct{}

// Spec describes the SSH handshake unit.
// What: Profile gate `ssh`, `--active` required.
// Why: Same active-probe discipline as the banner unit.
func (SSHHandshakeDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDSSHHandshake,
		Name:            "SSH KEXINIT algorithm audit",
		Description:     "Sends one fixed client proposal and classifies the offered KEX, host key, cipher and MAC algorithms; no key exchange and no authentication.",
		RuleID:          "GASH-054",
		CWE:             "CWE-327",
		Oracle:          "ssh",
		Severity:        plugin.SeverityMedium,
		Phase:           plugin.PhaseRecon,
		Order:           150,
		Gate:            "ssh",
		RequiresActive:  true,
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: detectorVersionProto,
	}
}

// Run audits KEXINIT for every infra target.
// What: Same target selection, scope, limiter, and semaphore as the banner unit.
// Why: Two SSH units sharing one concurrency budget is what keeps the phase
// within the configured infra limits.
func (SSHHandshakeDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	res := detector.Result{Stats: map[string]int{"ssh_handshake_checks": 0}}
	if env.Infra.Targets == nil {
		return res, nil
	}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		out  []*finding.Finding
		seen int
	)
	for _, addr := range env.Infra.Targets(defaultSSHPort) {
		h, p, aerr := net.SplitHostPort(addr)
		if aerr != nil {
			continue
		}
		if !allowed(env, h) {
			res.Skips = append(res.Skips, plugin.SkippedPlugin{
				PluginID: PluginIDSSHHandshake,
				Reason:   "skipped (infra target " + addr + " outside scope, no socket opened)",
			})
			continue
		}
		wg.Add(1)
		go func(h, p string) {
			defer wg.Done()
			if !acquire(env, ctx) {
				return
			}
			defer release(env)
			if !wait(env, ctx) {
				return
			}
			c, cancel := context.WithTimeout(ctx, infraTimeout(env))
			defer cancel()
			obs, err := AuditSSHHandshake(c, h, p, infraOptions(env))
			mu.Lock()
			defer mu.Unlock()
			seen++
			if err != nil || obs == nil {
				return
			}
			out = append(out, findingsOf(SSHHandshakeFindings(env.Target, obs))...)
		}(h, p)
	}
	wg.Wait()
	res.Stats["ssh_handshake_checks"] = seen
	res.Findings = out
	return res, nil
}

// DBPortsDetector inventories database ports (GASH-053).
// What: One harmless connect per host and port, bounded by the port ceiling.
// Why: An open port is a fact worth reporting; the unit reads no data.
type DBPortsDetector struct{}

// Spec describes the database port inventory unit.
// What: Profile gate `db`, `--active` required.
// Why: Port scanning is active traffic by definition.
func (DBPortsDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDDBPorts,
		Name:            "Database port inventory",
		Description:     "Connects to the normalized database port list per host and reports open ports with the greeting observed; no credentials and no data read.",
		RuleID:          "GASH-053",
		CWE:             "CWE-200",
		Oracle:          "db",
		Severity:        plugin.SeverityMedium,
		Phase:           plugin.PhaseRecon,
		Order:           160,
		Gate:            "db",
		RequiresActive:  true,
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: detectorVersionProto,
	}
}

// Run scans the port list for every host.
// What: Scope-denied hosts produce a skip and open no socket.
// Why: Same fail-closed discipline as the SSH units.
func (DBPortsDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	res := detector.Result{Stats: map[string]int{"db_ports_scanned": 0, "db_open_ports": 0}}
	if env.Infra.Hosts == nil || env.Infra.DBPorts == nil {
		return res, nil
	}
	ports := env.Infra.DBPorts()
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		out       []*finding.Finding
		scanned   int
		openPorts int
	)
	for _, h := range env.Infra.Hosts() {
		if !allowed(env, h) {
			res.Skips = append(res.Skips, plugin.SkippedPlugin{
				PluginID: PluginIDDBPorts,
				Reason:   "skipped (infra target " + h + " outside scope, no socket opened)",
			})
			continue
		}
		for _, port := range ports {
			port := port
			wg.Add(1)
			go func(h string, port int) {
				defer wg.Done()
				if !acquire(env, ctx) {
					return
				}
				defer release(env)
				if !wait(env, ctx) {
					return
				}
				c, cancel := context.WithTimeout(ctx, infraTimeout(env))
				defer cancel()
				results, err := ScanDBPorts(c, h, []int{port}, infraOptions(env))
				if err != nil || len(results) == 0 {
					return
				}
				fs := DBPortFindings(results)
				mu.Lock()
				defer mu.Unlock()
				scanned += len(results)
				for _, r := range results {
					if r.Open {
						openPorts++
					}
				}
				out = append(out, findingsOf(fs)...)
			}(h, port)
		}
	}
	wg.Wait()
	res.Stats["db_ports_scanned"] = scanned
	res.Stats["db_open_ports"] = openPorts
	res.Findings = out
	return res, nil
}

// DBUnauthDetector probes unauthenticated database access (GASH-055).
// What: One harmless request per host and port with a fixed dummy identity.
// Why: A missing authentication check is a real finding; no credential is ever
// guessed and no data is read.
type DBUnauthDetector struct{}

// Spec describes the database unauthenticated-access unit.
// What: Profile gate `db`, `--active` required.
// Why: The probe writes a request to the service, so it is active traffic.
func (DBUnauthDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDDBUnauth,
		Name:            "Database unauthenticated access",
		Description:     "Sends one harmless request per database port with a fixed dummy identity and reports whether the service answered without authentication.",
		RuleID:          "GASH-055",
		CWE:             "CWE-306",
		Oracle:          "db",
		Severity:        plugin.SeverityHigh,
		Phase:           plugin.PhaseRecon,
		Order:           170,
		Gate:            "db",
		RequiresActive:  true,
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: detectorVersionProto,
	}
}

// Run probes every host and port of the normalized list.
// What: Same list, scope, limiter and semaphore as the port inventory.
// Why: One shared budget for both database units keeps the phase bounded.
func (DBUnauthDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	res := detector.Result{Stats: map[string]int{"db_unauth_checks": 0}}
	if env.Infra.Hosts == nil || env.Infra.DBPorts == nil {
		return res, nil
	}
	ports := env.Infra.DBPorts()
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		out  []*finding.Finding
		seen int
	)
	for _, h := range env.Infra.Hosts() {
		if !allowed(env, h) {
			res.Skips = append(res.Skips, plugin.SkippedPlugin{
				PluginID: PluginIDDBUnauth,
				Reason:   "skipped (infra target " + h + " outside scope, no socket opened)",
			})
			continue
		}
		for _, port := range ports {
			port := port
			wg.Add(1)
			go func(h string, port int) {
				defer wg.Done()
				if !acquire(env, ctx) {
					return
				}
				defer release(env)
				if !wait(env, ctx) {
					return
				}
				c, cancel := context.WithTimeout(ctx, infraTimeout(env))
				defer cancel()
				obs, err := CheckDBUnauth(c, h, port, infraOptions(env))
				mu.Lock()
				defer mu.Unlock()
				seen++
				if err != nil || obs == nil {
					return
				}
				out = append(out, findingsOf(DBUnauthFindings(env.Target, *obs))...)
			}(h, port)
		}
	}
	wg.Wait()
	res.Stats["db_unauth_checks"] = seen
	res.Findings = out
	return res, nil
}

// allowed reports whether a host passes the phase scope decision.
// What: A nil decision denies everything (fail-closed).
// Why: The infra units must never dial a host the engine did not allow.
func allowed(env *detector.Env, host string) bool {
	return env.Infra.Allow != nil && env.Infra.Allow(host)
}

// acquire takes one shared concurrency slot.
// What: False means the scan was cancelled or the phase is unconfigured.
// Why: Without a limiter (library callers) the unit must not dial unbounded.
func acquire(env *detector.Env, ctx context.Context) bool {
	if env.Infra.Limiter == nil {
		return false
	}
	return env.Infra.Limiter.Acquire(ctx)
}

// release returns one shared concurrency slot.
func release(env *detector.Env) {
	if env.Infra.Limiter != nil {
		env.Infra.Limiter.Release()
	}
}

// wait blocks on the shared rate limiter.
func wait(env *detector.Env, ctx context.Context) bool {
	if env.Infra.Limiter == nil {
		return false
	}
	return env.Infra.Limiter.Wait(ctx)
}

// infraTimeout is the per-observation socket ceiling.
// What: A non-positive timeout falls back to the legacy 5 s default.
// Why: The units must behave identically to the pre-port engine when the caller
// left the timeout unset.
func infraTimeout(env *detector.Env) time.Duration {
	if env.Infra.Timeout > 0 {
		return env.Infra.Timeout
	}
	return 5 * time.Second
}

// DBPortsNormalized returns the port list capped by a ceiling.
// What: Default list when the operator supplied none.
// Why: Both database units must iterate the identical list; keeping the
// normalization here makes that guarantee local to the package.
func DBPortsNormalized(ports []int, max int) []int {
	if len(ports) == 0 {
		ports = DefaultDBPorts()
	}
	if max <= 0 {
		max = 20
	}
	if len(ports) > max {
		ports = ports[:max]
	}
	return ports
}
