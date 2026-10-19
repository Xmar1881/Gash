// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

// ProcSample is a best-effort CPU/memory observation of one tool process.
type ProcSample struct {
	CPUTimeMS int64
	MaxRSSKB  int64
}
