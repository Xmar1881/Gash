//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

// procWatcher is a no-op outside Linux: child CPU/memory sampling has no
// portable implementation here, so the report records CPU/mem as N/A on this
// platform instead of guessing.
type procWatcher struct{}

func startProcWatcher(pid int) (*procWatcher, error) { return nil, nil }

func (w *procWatcher) Stop() *ProcSample { return nil }
