// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// PluginFunc plugin mantığıdır (Tier1/Tier2/Tier3 adaptörleri buna dönüşür).
// Yanlış dönüş tipi/şema = plugin hatası (B7); tip sistemi bunu zorlar.
type PluginFunc func(ctx context.Context) ([]Candidate, error)

// Execute her plugin çağrısını recover() ile sarar → panic bile PluginResult'a döner (B7).
// Timeout: kooperatif (fn ctx'i dinler) + non-kooperatif (goroutine yarışı) ikisi de desteklenir.
// Tier2 vm.Interrupt / Tier3 kill zinciri loader'dadır; bu fonksiyon generic garantidir.
func Execute(ctx context.Context, pluginID string, fn PluginFunc) (res PluginResult) {
	res.PluginID = pluginID

	// Çağrı öncesi iptal kontrolü (bütçe yakma).
	select {
	case <-ctx.Done():
		res.Status = StatusTimeout
		res.Reason = fmt.Sprintf("before run: %v", ctx.Err())
		return res
	default:
	}

	type outcome struct {
		cands []Candidate
		err   error
		pan   any
	}
	ch := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if r := recover(); r != nil {
				o.pan = r
			}
			ch <- o
		}()
		o.cands, o.err = fn(ctx)
	}()

	select {
	case <-ctx.Done():
		res.Status = StatusTimeout
		res.Reason = fmt.Sprintf("timeout/cancel: %v", ctx.Err())
		return res
	case o := <-ch:
		if o.pan != nil {
			res.Status = StatusPanic
			res.Reason = fmt.Sprintf("panic: %v", o.pan)
			return res
		}
		if o.err != nil {
			switch {
			case errors.Is(o.err, ErrPolicyViolation):
				res.Status = StatusPolicyError
			case errors.Is(o.err, ErrBudgetExceeded),
				errors.Is(o.err, ErrRateLimited):
				// Bütçe/rate tavanı: plugin koştu ama bitiremedi. "skipped"
				// demek yanıltıcıydı (kısmi sonuç olabilir).
				res.Status = StatusPartial
			case errors.Is(o.err, ErrScopeViolation):
				res.Status = StatusSkipped
			case errors.Is(o.err, context.DeadlineExceeded):
				res.Status = StatusTimeout
			case errors.Is(o.err, context.Canceled):
				res.Status = StatusTimeout
			default:
				if ctx.Err() != nil {
					res.Status = StatusTimeout
				} else {
					res.Status = StatusError
				}
			}
			res.Reason = o.err.Error()
			return res
		}
		if ctx.Err() != nil {
			res.Status = StatusTimeout
			res.Reason = fmt.Sprintf("finished after cancel: %v", ctx.Err())
			return res
		}
		res.Status = StatusOK
		res.Candidates = o.cands
		return res
	}
}

// ExecuteWithTimeout per-plugin timeout uygular (--plugin-timeout, default 60s).
func ExecuteWithTimeout(parent context.Context, pluginID string, timeout time.Duration, fn PluginFunc) PluginResult {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return Execute(ctx, pluginID, fn)
}
