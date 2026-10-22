//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// procTickHz is the assumed USER_HZ for utime/stime accounting (Linux default).
const procTickHz = 100

type procWatcher struct {
	stop chan struct{}
	done chan ProcSample
}

func startProcWatcher(pid int) (*procWatcher, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("bench: invalid pid %d", pid)
	}
	w := &procWatcher{stop: make(chan struct{}), done: make(chan ProcSample, 1)}
	go func() {
		defer close(w.done)
		var best ProcSample
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		read := func() {
			if sample, ok := readProc(pid); ok {
				if sample.CPUTimeMS > best.CPUTimeMS {
					best.CPUTimeMS = sample.CPUTimeMS
				}
				if sample.MaxRSSKB > best.MaxRSSKB {
					best.MaxRSSKB = sample.MaxRSSKB
				}
			}
		}
		read()
		for {
			select {
			case <-w.stop:
				read()
				w.done <- best
				return
			case <-ticker.C:
				read()
			}
		}
	}()
	return w, nil
}

func (w *procWatcher) Stop() *ProcSample {
	if w == nil {
		return nil
	}
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	sample := <-w.done
	return &sample
}

func readProc(pid int) (ProcSample, bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ProcSample{}, false
	}
	s := string(stat)
	close := strings.LastIndex(s, ")")
	if close < 0 || close+2 >= len(s) {
		return ProcSample{}, false
	}
	fields := strings.Fields(s[close+2:])
	if len(fields) < 13 {
		return ProcSample{}, false
	}
	utime, _ := strconv.ParseInt(fields[11], 10, 64)
	stime, _ := strconv.ParseInt(fields[12], 10, 64)
	sample := ProcSample{CPUTimeMS: (utime + stime) * 1000 / procTickHz}
	if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					v, _ := strconv.ParseInt(parts[1], 10, 64)
					sample.MaxRSSKB = v
				}
				break
			}
		}
	}
	return sample, true
}
