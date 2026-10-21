//go:build deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"

	"github.com/Xmar1881/Gash/internal/headless"
)

// browserVerify runs the controlled headless-Chrome proof: the payload URL
// must trigger an observable canary while the neutral control stays clean.
func browserVerify(ctx context.Context, payloadURL, controlURL, auth string) (bool, error) {
	res, err := headless.VerifyXSSWithAuth(ctx, payloadURL, controlURL, auth, headless.DefaultTimeout)
	if err != nil {
		return false, err
	}
	return res.Triggered && res.ControlClean, nil
}

// browserVerifyUnavailable reports whether the deep build still lacks Chrome.
func browserVerifyUnavailable() bool { return !headless.Available() }
