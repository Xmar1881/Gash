// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/detector/detector.go
// What: Engine-owned detector port: the single contract every scan unit that
// cannot live in YAML or the JS sandbox implements (raw sockets, browser
// surface harvesting, media-type-less byte analysis).
// Why: Before this port these units were hardcoded if-chains inside the engine
// (internal/engine/scan_exec.go), so their identity, rule mapping, gates,
// telemetry keys, and extension points lived only in Go control flow. The port
// keeps the engine as carrier/budget manager/oracle decider while each unit
// owns its own spec, logic, payload data, and stats keys.

package detector

import (
	"context"
	"time"

	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

// Spec is the declarative identity of one engine-owned detector.
// What: The metadata the engine needs to gate, run, report, and document a unit.
// Why: One source of truth per detector: the same struct feeds the registry,
// the audit-trailed skip reasons, the report stats, and the inventory docs.
type Spec struct {
	// ID is the stable detector identity and the PolicySession identity
	// (e.g. "engine-smuggle-recon"). It appears in findings and skip records.
	ID string
	// Name is the human-readable detector name.
	Name string
	// Description explains what the detector proves and why it is engine-owned.
	Description string
	// RuleID is the taxonomy rule this detector reports (GASH-*).
	RuleID string
	// CWE is the weakness class of the rule.
	CWE string
	// Oracle names the evidence discipline the detector's findings carry.
	Oracle string
	// Severity is the declared severity; the engine still derives the final one
	// from evidence (B3 discipline).
	Severity plugin.Severity
	// Phase is the pipeline phase the detector belongs to.
	Phase plugin.Phase
	// Order is the deterministic execution order inside a phase.
	Order int
	// Gate is the profile detector name that must be enabled ("" = no profile
	// gate). Profile lists live in internal/config (ActiveDetectors).
	Gate string
	// RequiresActive marks a state-changing or invasive detector.
	RequiresActive bool
	// RequiresDeep marks a detector that only runs in deep mode.
	RequiresDeep bool
	// RequiresAggressive marks a detector with aggressive-profile-only volume.
	RequiresAggressive bool
	// SkipSubject is the audit-trail subject used in "requires" skip reasons
	// ("" = the reason names the requirement only, e.g. "skipped (requires --active)").
	SkipSubject string
	// MaxRequests is the declared request budget ceiling (0 = unbounded).
	MaxRequests int
	// Docs is the repository-relative documentation path for this detector's
	// evidence discipline ("" when the inventory page is the only reference).
	Docs string
	// DetectorVersion is the detector API version for traceability.
	DetectorVersion string
}

// Detector runs one engine-owned scan unit.
// What: Spec plus a single Run entry point over a brokered environment.
// Why: The engine stays the carrier (it decides the phase, builds the env, and
// applies budgets) while the detector owns its own probing and evidence logic.
type Detector interface {
	// Spec returns the detector identity and gates.
	Spec() Spec
	// Run executes the detector. An error means the detector failed; it never
	// aborts the scan (B7), and a failed detector emits no finding.
	Run(ctx context.Context, env *Env) (Result, error)
}

// Result is what one detector run produces.
// What: Findings plus audit counters plus optional scan-surface contributions.
// Why: Engine-owned detectors have three legitimate outputs (findings,
// telemetry, discovered surface); naming them explicitly keeps the engine's
// orchestration free of per-detector special cases.
type Result struct {
	// Findings are fully built findings (engine-recon bypasses finding.Build on
	// purpose: the detector owns its evidence discipline).
	Findings []*finding.Finding
	// Stats are the detector's report counters, keyed by their final report
	// name (e.g. "smuggle_requests", "spa_state_pages").
	Stats map[string]int
	// Requests is the number of requests the detector issued, when measurable.
	Requests int
	// Surface lists injection points the detector wants the scan to probe
	// (endpoint harvesting). The engine converts them to plugin points.
	Surface []Surface
	// Paths lists artifact paths the detector found (wordlist discovery). The
	// engine decides whether they feed a follow-up crawl; the detector only
	// reports what it observed.
	Paths []string
	// Carry is a detector-owned value the engine must hand to a later unit
	// without interpreting it (for example an already-paid handshake
	// observation the deep-TLS unit must reuse instead of dialing again).
	// Opaque to the port on purpose: the port never imports a protocol package.
	Carry any
	// Skips is the detector's own audit trail: every gate refusal it reached at
	// run time (per-target scope denials, target-shape refusals). The engine
	// forwards them verbatim, so a unit can never drop a decision silently.
	Skips []plugin.SkippedPlugin
}

// Flags is the effective scan policy visible to detectors.
// What: Read-only view of the activation flags and the profile name.
// Why: Detectors must be able to explain their own gates in the report, and
// the engine must not pass mutable config pointers into detector code.
type Flags struct {
	// Active is --active.
	Active bool
	// Deep is --deep.
	Deep bool
	// Aggressive reports the aggressive profile (the only profile that enables
	// invasive detectors such as the raw-TCP smuggling probe).
	Aggressive bool
	// Profile is the effective profile name, used verbatim in skip reasons.
	Profile string
}

// OOB is the out-of-band context handed to detectors.
// What: Whether a server is configured plus its namespace.
// Why: Detectors that need callbacks must skip honestly when it is unset
// instead of inventing a tentative finding.
type OOB struct {
	Enabled   bool
	ServerURL string
	Namespace string
}

// Page is one already-fetched body visible to detector code.
// What: Neutral carrier for crawler output (no discovery import, so the
// analysis packages can implement detectors without an import cycle).
// Why: GASH-071/072 style detectors observe bytes the crawler already paid
// for; they must see exactly those bytes, not a re-fetch.
type Page struct {
	// URL is the source URL.
	URL string
	// Body is the fetched body.
	Body []byte
	// JS marks a JavaScript source (as opposed to an HTML page).
	JS bool
	// Inline marks an inline script already contained in a page body.
	Inline bool
}

// Surface is one injection point a detector contributes to the scan.
// What: Detector-owned surface item mapped to a plugin point by the engine.
// Why: Passive recon discovers points as a side effect of analysis; the
// contribution belongs to the detector's result, not to engine control flow.
type Surface struct {
	// URL is the point URL.
	URL string
	// Method is the HTTP method.
	Method string
	// ParamName is the injectable parameter name.
	ParamName string
	// ParamLocation is query/hash/fragment/body/header/path/cookie.
	ParamLocation string
	// Value is the current parameter value.
	Value string
	// SourceKind names the client-side source family.
	SourceKind string
	// FormValues replays the full form with the target field replaced.
	FormValues map[string]string
	// FormEnctype is the owning form's encoding.
	FormEnctype string
}

// Crawl is the neutral crawler summary some detectors need.
// What: Counters plus the JavaScript sources the crawler already fetched.
// Why: Passive JS analysis must observe every source the crawler paid for
// (inline scripts included), so it needs a source list rather than the page
// view the byte-analysis detectors use.
type Crawl struct {
	// JSFilesFetched counts the JavaScript files the crawler fetched.
	JSFilesFetched int
	// JSSources lists every JavaScript source, inline scripts included.
	JSSources []Page
}

// Infra is the carrier capability set for protocol-level recon units.
// What: The policy-filtered inputs a raw protocol observation needs: timeout,
// host scope, the shared concurrency/rate limiter, the operator's target lists,
// and the already-paid handshake observation.
// Why: These units dial hosts directly (TLS handshake, DNS query, TCP connect,
// SSH/D… banners). The engine must stay the only owner of scope, rate limits,
// parallelism, and the one-observation-per-phase memo, otherwise a unit could
// bypass the scan budget or dial a host the operator never allowed.
type Infra struct {
	// Timeout is the per-observation socket ceiling.
	Timeout time.Duration
	// Allow is the host-level scope decision; nil means every host is denied.
	Allow func(host string) bool
	// Limiter is the shared concurrency plus rate gate for this phase.
	Limiter InfraLimiter
	// Targets returns scope-eligible host:port addresses for a service default
	// port (the operator's explicit infra targets, else the scan target).
	Targets func(servicePort string) []string
	// Hosts returns the host list a port inventory iterates.
	Hosts func() []string
	// DBPorts returns the normalized, capped port list for database checks.
	DBPorts func() []int
	// TCPBanners is the operator's explicit banner target list; the unit is
	// silent when it is empty.
	TCPBanners []string
	// TLSAuditDeep enables the deep certificate/version audit branch.
	TLSAuditDeep bool
	// TLSObservation is the memoized handshake observation of this phase (an
	// already-paid dial), or nil. Opaque to the port.
	TLSObservation any
}

// InfraLimiter bounds protocol-level recon traffic.
// What: A shared semaphore plus optional rate limiter owned by the engine.
// Why: Per-unit limiters would multiply the effective concurrency; one shared
// instance keeps the phase inside the single budget the operator configured.
type InfraLimiter interface {
	// Acquire blocks until the caller may proceed; false when cancelled.
	Acquire(ctx context.Context) bool
	// Release returns one slot.
	Release()
	// Wait blocks on the configured rate limit; always true when unset.
	Wait(ctx context.Context) bool
}

// Env is the brokered environment a detector runs against.
// What: The engine passes only policy-filtered capabilities: a probe client on
// the shared PolicySession, already-fetched pages, the scope decision, the
// activation flags, and the OOB context.
// Why: Detectors must not open their own transport for HTTP work: every HTTP
// request has to travel through the same budget, scope, rate, and
// safe-method checks as the rest of the scan (B6 discipline).
type Env struct {
	// Target is the validated target URL.
	Target string
	// Probe issues policy-filtered HTTP requests. Nil when the pipeline has no
	// HTTP client (static-only phases).
	Probe *probe.Client
	// Pages holds the already-fetched crawl bodies.
	Pages []Page
	// Crawl holds the crawler summary (counters plus JS sources).
	Crawl Crawl
	// Tech is the detected technology set (fingerprint-driven detectors).
	Tech []string
	// Scope decides whether a host may be contacted. Nil means no --scope was
	// given (open mode, operator responsibility).
	Scope func(host string) bool
	// URLAllowed decides whether a URL discovered inside fetched content may be
	// contacted. What: The engine's URL-level scope decision (target origin
	// always allowed, third parties only with --scope).
	// Why: Passive recon harvests URLs from bodies; the detector must not
	// re-implement scope, and a third-party endpoint must never be dialed.
	URLAllowed func(rawURL string) bool
	// FollowCrawl fetches one page for a parameterless endpoint and returns the
	// surface it exposed. What: A bounded, scope-checked single-page crawl.
	// Why: Endpoint harvesting needs a follow-up observation, but the bound
	// (one page, depth zero) and the scope check stay engine-owned.
	FollowCrawl func(ctx context.Context, rawURL string) ([]Surface, error)
	// Flags is the effective scan policy.
	Flags Flags
	// OOB is the out-of-band context.
	OOB OOB
	// Infra carries the protocol-level recon capabilities.
	Infra Infra
	// Log writes a structured line through the engine logger (never stdout).
	Log func(level, msg string)
}

// logf calls the env logger when set.
// What: Nil-safe logging helper shared by detectors.
// Why: Detector code must not branch on logger presence in every call site.
func (e *Env) logf(level, msg string) {
	if e == nil || e.Log == nil {
		return
	}
	e.Log(level, msg)
}

// LogInfo writes an info line through the engine logger.
// What: Public nil-safe wrapper for detectors.
// Why: Keeps the logger contract in one place instead of per-detector checks.
func (e *Env) LogInfo(msg string) { e.logf("info", msg) }

// LogWarn writes a warning line through the engine logger.
// What: Public nil-safe wrapper for detectors.
// Why: Skipped or unmeasurable detector work must leave an audit trail.
func (e *Env) LogWarn(msg string) { e.logf("warn", msg) }

// pagesByKind returns the pages a content detector should scan: HTML pages
// first, then external JavaScript sources, skipping inline scripts that are
// already part of a page body.
// What: Shared page-selection rule for byte-analysis detectors.
// Why: GASH-071/072 and their successors must agree on which bytes are theirs
// to scan, otherwise duplicate findings appear as the catalog grows.
func (e *Env) pagesByKind() []Page {
	if e == nil || len(e.Pages) == 0 {
		return nil
	}
	out := make([]Page, 0, len(e.Pages))
	for _, p := range e.Pages {
		if p.JS && p.Inline {
			continue
		}
		out = append(out, p)
	}
	return out
}

// PagesForScan exposes pagesByKind to implementers.
// What: The engine-sanctioned page view for content detectors.
// Why: One exported accessor keeps the selection rule auditable and shared.
func (e *Env) PagesForScan() []Page { return e.pagesByKind() }
