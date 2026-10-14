// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package engine provides centralized scope management for scan targets.
// What: Host/port/proto/path allowlist, redirect re-validation, IP change detection.
// Why: Single audit point for "only allowed targets are requested" (P1.3).
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// ScopeManager manages allowed targets and validates requests against scope.
// What: Central authority for target allow/deny decisions.
// Why: Prevents unbounded scans, enforces redirect re-validation, detects DNS rebinding.
type ScopeManager struct {
	mu sync.RWMutex

	// Allowed entries: domain, CIDR, or exact URL prefix
	allowedEntries []ScopeEntry
	// Resolved IPs for domain entries (for rebinding detection)
	resolvedIPs map[string][]net.IP
	// Resolved IPs for the original target (for change detection)
	targetIPs map[string][]net.IP
	// Original target for cross-reference
	originalTarget string
	// Resolver for DNS lookups
	resolver *net.Resolver
	// Cache TTL for DNS resolutions
	cacheTTL time.Duration
}

// ScopeEntry represents a single scope allowlist entry.
type ScopeEntry struct {
	Type     ScopeEntryType // Domain, CIDR, URLPrefix
	Value    string         // Domain name, CIDR notation, or URL prefix
	Port     int            // Optional port restriction (0 = any)
	Protocol string         // Optional protocol restriction (http/https, empty = any)
	Path     string         // Optional path prefix restriction
}

// ScopeEntryType classifies the type of scope entry.
type ScopeEntryType int

const (
	ScopeTypeDomain    ScopeEntryType = iota // Domain or subdomain (e.g., example.com)
	ScopeTypeCIDR                            // CIDR block (e.g., 192.168.1.0/24)
	ScopeTypeURLPrefix                       // URL prefix (e.g., https://example.com/api/)
)

// NewScopeManager creates a scope manager from scope entries.
func NewScopeManager(entries []string) *ScopeManager {
	sm := &ScopeManager{
		allowedEntries: make([]ScopeEntry, 0, len(entries)),
		resolvedIPs:    make(map[string][]net.IP),
		targetIPs:      make(map[string][]net.IP),
		resolver:       &net.Resolver{},
		cacheTTL:       5 * time.Minute,
	}
	for _, e := range entries {
		if parsed := sm.parseEntry(e); parsed != nil {
			sm.allowedEntries = append(sm.allowedEntries, *parsed)
		}
	}
	return sm
}

// parseEntry parses a scope entry string into a ScopeEntry.
func (sm *ScopeManager) parseEntry(entry string) *ScopeEntry {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}

	// CIDR check
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return &ScopeEntry{Type: ScopeTypeCIDR, Value: entry}
	}

	// URL prefix check
	if strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://") {
		u, err := url.Parse(entry)
		if err != nil {
			return nil
		}
		se := &ScopeEntry{
			Type:     ScopeTypeURLPrefix,
			Value:    u.Host,
			Protocol: u.Scheme,
			Path:     strings.TrimSuffix(u.Path, "/"),
		}
		return se
	}

	// Domain entry
	return &ScopeEntry{Type: ScopeTypeDomain, Value: strings.ToLower(entry)}
}

// SetOriginalTarget records the original scan target for cross-reference.
func (sm *ScopeManager) SetOriginalTarget(target string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.originalTarget = target
	u, _ := url.Parse(target)
	if u != nil {
		sm.resolveAndCache(u.Hostname())
	}
}

// resolveAndCache resolves a hostname and caches IPs.
func (sm *ScopeManager) resolveAndCache(host string) []net.IP {
	if ips, ok := sm.resolvedIPs[host]; ok {
		return ips
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := sm.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	var ipList []net.IP
	for _, ip := range ips {
		ipList = append(ipList, ip.IP)
	}
	sm.resolvedIPs[host] = ipList
	return ipList
}

// CheckScope validates a URL against the scope.
// What: Returns nil if allowed, error with classification if denied.
// Why: Single point for all scope decisions (initial + redirects).
func (sm *ScopeManager) CheckScope(ctx context.Context, u *url.URL) error {
	sm.mu.RLock()
	entries := sm.allowedEntries
	originalTarget := sm.originalTarget
	sm.mu.RUnlock()

	if len(entries) == 0 {
		// Implicit scope: only the original target is allowed
		if originalTarget != "" {
			origU, _ := url.Parse(originalTarget)
			if origU != nil && sm.sameTarget(u, origU) {
				return nil
			}
			return &ScopeError{Op: "implicit-scope", URL: u.String(), Err: fmt.Errorf("%w: target %s not in implicit scope (original: %s)", plugin.ErrScopeViolation, u.String(), originalTarget)}
		}
		return nil // No scope configured = allow all (backward compat for tests)
	}

	host := strings.ToLower(u.Hostname())
	scheme := strings.ToLower(u.Scheme)
	path := strings.TrimSuffix(u.Path, "/")
	port := u.Port()

	for _, e := range entries {
		if sm.matchEntry(u, host, scheme, path, port, e) {
			// Additional IP rebinding check for domain entries
			if e.Type == ScopeTypeDomain {
				if err := sm.checkIPRebinding(ctx, host, e.Value); err != nil {
					return err
				}
			}
			return nil
		}
	}

	return &ScopeError{Op: "scope-mismatch", URL: u.String(), Err: fmt.Errorf("%w: host %s not in scope", plugin.ErrScopeViolation, host)}
}

// matchEntry checks if a URL matches a scope entry.
func (sm *ScopeManager) matchEntry(u *url.URL, host, scheme, path, port string, e ScopeEntry) bool {
	switch e.Type {
	case ScopeTypeDomain:
		// Exact domain or subdomain match
		if host == e.Value || strings.HasSuffix(host, "."+e.Value) {
			if e.Protocol != "" && scheme != e.Protocol {
				return false
			}
			if e.Port > 0 && port != "" && port != fmt.Sprintf("%d", e.Port) {
				return false
			}
			if e.Path != "" && !strings.HasPrefix(path, e.Path) {
				return false
			}
			return true
		}
	case ScopeTypeCIDR:
		// Resolve host and check CIDR containment
		ips := sm.resolveAndCache(host)
		if ips == nil {
			return false // Unresolvable hosts don't match CIDR (fail-closed)
		}
		_, cidr, _ := net.ParseCIDR(e.Value)
		for _, ip := range ips {
			if cidr.Contains(ip) {
				return true
			}
		}
	case ScopeTypeURLPrefix:
		if host == e.Value || strings.HasSuffix(host, "."+e.Value) {
			if e.Protocol != "" && scheme != e.Protocol {
				return false
			}
			if !strings.HasPrefix(path, e.Path) {
				return false
			}
			return true
		}
	}
	return false
}

// checkIPRebinding detects DNS rebinding by comparing resolved IPs.
// What: Fails if hostname resolves to IPs outside the originally allowed CIDR/domain.
// Why: Prevents TOCTOU attacks where DNS changes after scope check.
func (sm *ScopeManager) checkIPRebinding(ctx context.Context, host, allowedDomain string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Get current IPs
	currentIPs := sm.resolveAndCache(host)
	if currentIPs == nil {
		return nil // Can't verify, allow (best-effort)
	}

	// Get allowed IPs for the domain entry
	allowedIPs := sm.resolvedIPs[allowedDomain]
	if allowedIPs == nil {
		// First time seeing this domain, resolve and cache
		allowedIPs = sm.resolveAndCache(allowedDomain)
		if allowedIPs == nil {
			return nil // Can't verify
		}
	}

	// Check if any current IP is not in allowed IPs
	for _, curr := range currentIPs {
		found := false
		for _, allowed := range allowedIPs {
			if curr.Equal(allowed) {
				found = true
				break
			}
		}
		if !found {
			return &ScopeError{
				Op:  "rebinding-detected",
				URL: host,
				Err: fmt.Errorf("%w: host %s resolved to new IP %s not in original allowlist", plugin.ErrScopeViolation, host, curr.String()),
			}
		}
	}
	return nil
}

// sameTarget checks if two URLs refer to the same target (scheme + host + port).
func (sm *ScopeManager) sameTarget(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		a.Port() == b.Port()
}

// ScopeError wraps scope violations with operation context.
type ScopeError struct {
	Op  string
	URL string
	Err error
}

func (e *ScopeError) Error() string {
	return fmt.Sprintf("scope %s: %s: %v", e.Op, e.URL, e.Err)
}

func (e *ScopeError) Unwrap() error { return e.Err }

// IsScopeError checks if an error is a scope violation.
func IsScopeError(err error) bool {
	var se *ScopeError
	return errors.As(err, &se)
}

// ValidateRequestSize checks request body size against limit.
func ValidateRequestSize(body []byte, limit int64) error {
	if limit > 0 && int64(len(body)) > limit {
		return fmt.Errorf("%w: request body %d bytes exceeds limit %d", plugin.ErrBudgetExceeded, len(body), limit)
	}
	return nil
}

// ValidateResponseSize checks response Content-Length against limit.
func ValidateResponseSize(contentLength int64, limit int64) error {
	if limit > 0 && contentLength > limit {
		return fmt.Errorf("%w: response body %d bytes exceeds limit %d", plugin.ErrBudgetExceeded, contentLength, limit)
	}
	return nil
}

// ScanBudget tracks total scan budget to prevent unlimited scans.
type ScanBudget struct {
	maxRequestsTotal   int64
	maxRequestsPerHost int64
	maxRequestsPerPath int64
	requestsTotal      atomic.Int64
	requestsPerHost    map[string]*atomic.Int64
	requestsPerPath    map[string]*atomic.Int64
	mu                 sync.Mutex
}

func NewScanBudget(maxTotal, maxPerHost, maxPerPath int64) *ScanBudget {
	return &ScanBudget{
		maxRequestsTotal:   maxTotal,
		maxRequestsPerHost: maxPerHost,
		maxRequestsPerPath: maxPerPath,
		requestsPerHost:    make(map[string]*atomic.Int64),
		requestsPerPath:    make(map[string]*atomic.Int64),
	}
}

func (sb *ScanBudget) hostKey(u *url.URL) string {
	return strings.ToLower(u.Hostname())
}

func (sb *ScanBudget) pathKey(u *url.URL) string {
	return strings.ToLower(u.Hostname() + u.Path)
}

func (sb *ScanBudget) counterFor(m map[string]*atomic.Int64, key string) *atomic.Int64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	c, ok := m[key]
	if !ok {
		c = &atomic.Int64{}
		m[key] = c
	}
	return c
}

func (sb *ScanBudget) CheckAndIncrement(u *url.URL) error {
	if sb.maxRequestsTotal > 0 && sb.requestsTotal.Load() >= sb.maxRequestsTotal {
		return fmt.Errorf("%w: total request budget %d exhausted", plugin.ErrBudgetExceeded, sb.maxRequestsTotal)
	}
	if sb.maxRequestsPerHost > 0 {
		if sb.counterFor(sb.requestsPerHost, sb.hostKey(u)).Add(1) > sb.maxRequestsPerHost {
			return fmt.Errorf("%w: per-host request budget %d exhausted for %s", plugin.ErrBudgetExceeded, sb.maxRequestsPerHost, sb.hostKey(u))
		}
	}
	if sb.maxRequestsPerPath > 0 {
		if sb.counterFor(sb.requestsPerPath, sb.pathKey(u)).Add(1) > sb.maxRequestsPerPath {
			return fmt.Errorf("%w: per-path request budget %d exhausted for %s", plugin.ErrBudgetExceeded, sb.maxRequestsPerPath, sb.pathKey(u))
		}
	}
	sb.requestsTotal.Add(1)
	return nil
}

func (sb *ScanBudget) Total() int64 { return sb.requestsTotal.Load() }
