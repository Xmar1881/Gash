// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"errors"
	"fmt"
)

// Sentinel hatalar; errors.Is/As ile test edilir (%w ile sarmalanır).
var (
	ErrValidation       = errors.New("plugin: validation failed")
	ErrPolicyViolation  = errors.New("plugin: policy violation")
	ErrBudgetExceeded   = errors.New("plugin: budget exceeded")
	ErrScopeViolation   = errors.New("plugin: scope violation")
	ErrRateLimited      = errors.New("plugin: rate limited")
	ErrTrustRequired    = errors.New("plugin: tier3 trust required")
	ErrOOBNotConfigured = errors.New("plugin: oob not configured")
	ErrCycleDetected    = errors.New("plugin: dependency cycle detected")
	ErrConflict         = errors.New("plugin: id conflict")
	ErrTimeout          = errors.New("plugin: timeout")
	ErrPanic            = errors.New("plugin: panic")
	ErrInvalidReturn    = errors.New("plugin: invalid return")
)

// ValidationError alan-bazlı detay taşır.
type ValidationError struct {
	PluginID string
	Field    string
	Rule     string
	Msg      string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("plugin %q: field %q rule %s: %s", e.PluginID, e.Field, e.Rule, e.Msg)
}

func (e *ValidationError) Unwrap() error { return ErrValidation }

// PolicyError PolicySession ihlallerini taşır.
type PolicyError struct {
	PluginID string
	Op       string
	Err      error
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("plugin %q policy %s: %v", e.PluginID, e.Op, e.Err)
}

func (e *PolicyError) Unwrap() error { return e.Err }

// CycleError döngüdeki id'leri listeler (fail-closed, kırma önerisiyle).
type CycleError struct {
	Cycle []string
}

func (e *CycleError) Error() string {
	return fmt.Sprintf("dependency cycle: %v (use --ignore-plugin to break)", e.Cycle)
}

func (e *CycleError) Unwrap() error { return ErrCycleDetected }
