// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package scaffold

import "errors"

// Sentinel errors for scaffold failures.
// What: Testable errors wrapped with %w by every generator path.
// Why: Callers distinguish bad input from existing files via errors.Is.
var (
	errScaffoldInvalid = errors.New("scaffold: invalid input")
	errScaffoldExists  = errors.New("scaffold: already exists")
)

// ErrInvalidInput reports bad id or tier values.
// What: Public alias for input validation failures.
// Why: The CLI maps this to exit code 2 without string matching.
var ErrInvalidInput = errScaffoldInvalid

// ErrAlreadyExists reports an existing output without --force.
// What: Public alias for overwrite refusals.
// Why: Lets automation detect the conflict and retry with --force.
var ErrAlreadyExists = errScaffoldExists
