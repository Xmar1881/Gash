//go:build !deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"
	"fmt"
)

// browserVerify is unavailable in the default build; scenarios that need a
// browser are reported unverified instead of being scored.
func browserVerify(ctx context.Context, payloadURL, controlURL string) (bool, error) {
	return false, fmt.Errorf("browser verification unavailable: default build links no browser (rebuild with -tags deep and Chrome); scenario stays unverified")
}

// browserVerifyUnavailable reports the stub build to the limitations list.
func browserVerifyUnavailable() bool { return true }
