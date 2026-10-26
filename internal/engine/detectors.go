// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/engine/detectors.go
// What: Engine wiring for the detector port: registry construction, gate
// evaluation, environment adaptation, and one dispatch entry point.
// Why: The engine-owned scan units used to be hardcoded if-chains with their own
// gate wording, telemetry keys, and error handling. This file is the only place
// where the engine knows about them: it decides the phase and builds the
// brokered environment, the detector owns everything else.

package engine

import (
	"context"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/probe"
	"github.com/Xmar1881/Gash/internal/proto"
	"github.com/Xmar1881/Gash/internal/recon"
	"github.com/Xmar1881/Gash/internal/smuggle"
)

// jsReconURLAllowed JS endpoint/harita besleme kapısıdır.
// What: Hedef origin her zaman; diğer host'lar yalnızca explicit --scope
// içindeyse (ScopeManager: domain/CIDR/URL-prefix + rebinding).
// Why: Open modda üçüncü taraf endpoint takibi YAPILMAZ; kapsam verilmişse
// operatörün allowlist'i genişletir (fail-closed). Pasif recon dedektörü bu
// kararı env.URLAllowed üzerinden motor'dan alır; SPA yüzeyi de aynı kapıyı
// kullanır, böylece iki hat tek kapsam kuralına uyar.
func jsReconURLAllowed(target, u *url.URL, scope []string, sm *ScopeManager) bool {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if strings.EqualFold(target.Scheme, u.Scheme) && strings.EqualFold(target.Host, u.Host) {
		return true
	}
	if len(scope) == 0 {
		return false
	}
	return sm.CheckScope(context.Background(), u) == nil
}

// newDetectorRegistry builds the engine-owned detector registry.
// What: The explicit, enumerable list of units that cannot be YAML or JS
// plugins (raw sockets, byte analysis over crawler output, wordlist probing).
// Why: Registration is visible at one site, so "which engine-owned detectors
// exist" is answerable by reading a list instead of grepping control flow.
func newDetectorRegistry() *detector.Registry {
	reg := detector.NewRegistry()
	// Order follows the scan pipeline: passive analysis of the crawler's bytes
	// first, then request-heavy discovery, then the invasive raw-TCP probe.
	reg.MustRegister(recon.JSRecon{})
	reg.MustRegister(recon.SPAState{})
	reg.MustRegister(recon.DevBuild{})
	reg.MustRegister(discovery.ContentDetector{})
	reg.MustRegister(smuggle.Detector{})
	// Protocol-level recon units: they dial hosts directly (handshake, DNS
	// query, TCP connect, banners), so the engine only brokers scope, timeout,
	// the shared limiter, and the phase's handshake memo.
	reg.MustRegister(proto.TLSDetector{})
	reg.MustRegister(proto.DNSDetector{})
	reg.MustRegister(proto.TCPBannerDetector{})
	reg.MustRegister(proto.SSHBannerDetector{})
	reg.MustRegister(proto.SSHHandshakeDetector{})
	reg.MustRegister(proto.DBPortsDetector{})
	reg.MustRegister(proto.DBUnauthDetector{})
	reg.MustRegister(proto.TLSDeepDetector{})
	return reg
}

// DetectorSpecs returns the engine-owned detector specs in execution order.
// What: Read-only view for reporting, documentation, and parity tests.
// Why: The inventory must be derivable from the code, not maintained by hand.
func (e *Engine) DetectorSpecs() []detector.Spec {
	if e.detectors == nil {
		return nil
	}
	return e.detectors.Specs()
}

// detectorPolicy builds the gate input for engine-owned detectors.
// What: Effective flags plus the profile's enabled detector set.
// Why: Engine-owned units must be gated by exactly the same data the plugin
// scheduler uses, so no profile can run a unit it forbids.
func (e *Engine) detectorPolicy() detector.Policy {
	enabled := e.cfg.enabledDetectors
	if enabled == nil {
		enabled = map[string]bool{}
	}
	profile := ""
	if p := e.EffectiveProfile(); p != nil {
		profile = string(p.Name)
	}
	return detector.Policy{
		Flags: detector.Flags{
			Active:     e.cfg.Active,
			Deep:       e.cfg.Deep,
			Aggressive: e.cfg.Profile == config.ProfileAggressive,
			Profile:    profile,
		},
		Enabled: enabled,
	}
}

// detectorRun is the outcome of one gated detector invocation.
// What: Whether the detector ran, the gate reason when it did not, and the
// result when it did.
// Why: The engine must be able to record an audit-trailed skip exactly where it
// used to, without re-implementing the gate logic at every call site.
type detectorRun struct {
	// Ran reports whether the detector executed.
	Ran bool
	// Reason is the audit-trailed skip reason when a declared gate refused.
	Reason string
	// Result is the detector output when Ran is true.
	Result detector.Result
}

// runDetector gates and runs one engine-owned detector by id.
// What: Single dispatch entry point for every registry unit.
// Why: One place resolves the detector, applies the policy, converts failures
// into non-fatal outcomes (B7), and returns the uniform result shape.
func (e *Engine) runDetector(ctx context.Context, env *detector.Env, id string) detectorRun {
	if e.detectors == nil {
		return detectorRun{Reason: "skipped (detector " + id + " not registered)"}
	}
	d, ok := e.detectors.Get(id)
	if !ok {
		return detectorRun{Reason: "skipped (detector " + id + " not registered)"}
	}
	if allowed, reason := d.Spec().Evaluate(e.detectorPolicy()); !allowed {
		return detectorRun{Reason: reason}
	}
	res, err := d.Run(ctx, env)
	if err != nil {
		// A detector failure is never a scan failure (B7), and it is never
		// invented as an audit-trailed skip either: detectors report their own
		// honest skips through Result.Skipped (see the smuggling detector's
		// scope and HTTP/2 refusals). An error here means "unmeasurable".
		return detectorRun{}
	}
	return detectorRun{Ran: true, Result: res}
}

// detectorEnv builds the brokered environment for engine-owned detectors.
// What: Policy-filtered capabilities only: the shared probe client, the
// crawler's bytes, the tech set, the scope decision, the flags, and OOB state.
// Why: Detectors must not reach for engine internals; everything they are
// allowed to see is named here.
func (e *Engine) detectorEnv(target string, client *probe.Client, crawlRes *discovery.CrawlResult) *detector.Env {
	policy := e.detectorPolicy()
	env := &detector.Env{
		Target: target,
		Probe:  client,
		Pages:  detectorPages(crawlRes),
		Crawl:  detectorCrawl(crawlRes),
		Tech:   techNames(e.detectedTech),
		Flags:  policy.Flags,
		OOB: detector.OOB{
			Enabled:   e.cfg.OOBServer != "",
			ServerURL: e.cfg.OOBServer,
		},
	}
	env.URLAllowed = e.detectorURLAllowed(target)
	env.FollowCrawl = e.detectorFollowCrawl(client)
	return env
}

// detectorCrawl converts crawler output to the port's neutral summary.
// What: File counter plus the full JavaScript source list (inline included).
// Why: Passive JS analysis observes every source the crawler paid for, so it
// needs the raw list rather than the inline-filtered page view.
func detectorCrawl(crawlRes *discovery.CrawlResult) detector.Crawl {
	if crawlRes == nil {
		return detector.Crawl{}
	}
	out := detector.Crawl{JSFilesFetched: crawlRes.JSFilesFetched}
	for _, s := range crawlRes.JSSources {
		out.JSSources = append(out.JSSources, detector.Page{
			URL: s.URL, Body: s.Body, JS: true, Inline: s.Inline,
		})
	}
	return out
}

// detectorURLAllowed builds the URL-level scope decision for passive recon.
// What: The target origin is always allowed; every other host only with
// --scope, and only for http/https.
// Why: Harvested URLs come from fetched bodies, so the decision must be made
// per URL (scheme, host, and possibly path prefix) and never by the detector:
// a third-party endpoint is recorded but never requested.
func (e *Engine) detectorURLAllowed(target string) func(rawURL string) bool {
	targetParsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil || targetParsed.Host == "" {
		return func(string) bool { return false }
	}
	sm := NewScopeManager(e.cfg.Scope)
	sm.SetOriginalTarget(targetParsed.String())
	return func(raw string) bool {
		u, perr := url.Parse(strings.TrimSpace(raw))
		if perr != nil || u.Host == "" {
			return false
		}
		return jsReconURLAllowed(targetParsed, u, e.cfg.Scope, sm)
	}
}

// detectorFollowCrawl builds the bounded follow-up crawl capability.
// What: One page, depth zero, scope-checked, JS recon disabled, converted to
// neutral surface items.
// Why: Parameterless endpoints need an observation to harvest their form
// fields, but the bound and the scope policy stay engine-owned so a detector
// can never turn recon into unbounded crawling. Form replay metadata is
// deliberately not carried: this observation only names new points.
func (e *Engine) detectorFollowCrawl(client *probe.Client) func(ctx context.Context, rawURL string) ([]detector.Surface, error) {
	return func(ctx context.Context, rawURL string) ([]detector.Surface, error) {
		follow, err := discovery.Crawl(ctx, client, rawURL, discovery.CrawlOptions{
			MaxPages: 1, MaxDepth: 0, Scope: e.cfg.Scope,
			ReadRobots: false, ReadSitemap: false, SkipJSRecon: true,
		})
		if err != nil || follow == nil {
			return nil, err
		}
		out := make([]detector.Surface, 0, len(follow.SurfacePoints))
		for _, ip := range follow.SurfacePoints {
			out = append(out, detector.Surface{
				URL: ip.URL, Method: ip.Method, ParamName: ip.ParamName,
				ParamLocation: ip.ParamLocation, Value: ip.Value,
			})
		}
		return out, nil
	}
}

// detectorPages converts crawler output to the port's neutral page view.
// What: HTML pages first, then external JS sources, with inline scripts marked.
// Why: Byte-analysis detectors must observe exactly the bytes the pre-port code
// observed, in the same order, or findings and counters would drift.
func detectorPages(crawlRes *discovery.CrawlResult) []detector.Page {
	if crawlRes == nil {
		return nil
	}
	out := make([]detector.Page, 0, len(crawlRes.Pages)+len(crawlRes.JSSources))
	for _, p := range crawlRes.Pages {
		out = append(out, detector.Page{URL: p.URL, Body: p.Body})
	}
	for _, s := range crawlRes.JSSources {
		out = append(out, detector.Page{URL: s.URL, Body: s.Body, JS: true, Inline: s.Inline})
	}
	return out
}

// techNames converts the detected-tech set to a sorted slice.
// What: Deterministic tech list for fingerprint-driven detectors.
// Why: Map iteration order must never leak into detector behaviour.
func techNames(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// detectorScope builds the scope decision handed to raw-TCP detectors.
// What: nil when no --scope was given (open mode, operator responsibility);
// otherwise a deny-by-default check against the scope manager.
// Why: The smuggling probe dials hosts directly, so its scope preflight must
// run before any socket opens, and it must not inherit the target-host
// exemption the HTTP plugin path applies.
func (e *Engine) detectorScope(target string) func(host string) bool {
	if len(e.cfg.Scope) == 0 {
		return nil
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		// Scope configured but the target is unparseable: fail closed.
		return func(string) bool { return false }
	}
	sm := NewScopeManager(e.cfg.Scope)
	sm.SetOriginalTarget(targetURL.String())
	scheme := targetURL.Scheme
	port := targetURL.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return func(host string) bool {
		checkURL := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}
		return sm.CheckScope(context.Background(), checkURL) == nil
	}
}

// smugglerEnv is the smuggling detector's environment (scope-aware).
// What: The shared env plus the raw-TCP scope decision.
// Why: Only the raw-TCP probe consumes a host-level scope callback; keeping it
// out of the shared env documents that asymmetry.
func (e *Engine) smugglerEnv(target string, client *probe.Client, crawlRes *discovery.CrawlResult) *detector.Env {
	env := e.detectorEnv(target, client, crawlRes)
	env.Scope = e.detectorScope(target)
	return env
}
