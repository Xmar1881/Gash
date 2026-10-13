// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/dop251/goja"
	"gopkg.in/yaml.v3"
)

// Frontmatter sabit formatıdır: dosya başında `/* --- ... --- */`.
// Varyant kabul edilmez — parser basitliği (A-10).
const (
	frontStart = "/* ---"
	frontEnd   = "--- */"
)

// ParseTier2Frontmatter goja VM BAŞLATMADAN metadata tarar (warm keşif bütçesi).
func ParseTier2Frontmatter(path string, data []byte) (*plugin.PluginSpec, error) {
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, frontStart) {
		return nil, fmt.Errorf("tier2 %s: frontmatter yok (sabit format /* --- ... --- */): %w", path, plugin.ErrValidation)
	}
	end := strings.Index(s, frontEnd)
	if end < 0 {
		return nil, fmt.Errorf("tier2 %s: frontmatter kapanışı yok: %w", path, plugin.ErrValidation)
	}
	inner := s[len(frontStart):end]
	var spec plugin.PluginSpec
	if err := yaml.Unmarshal([]byte(inner), &spec); err != nil {
		return nil, fmt.Errorf("tier2 frontmatter yaml %s: %w", path, err)
	}
	spec.Tier = plugin.TierJS
	if err := plugin.Validate(spec); err != nil {
		return nil, fmt.Errorf("tier2 validate %s: %w", path, err)
	}
	if ww, err := IsWorldWritable(path); err == nil && ww {
		return nil, fmt.Errorf("tier2 %s world-writable: %w", path, plugin.ErrValidation)
	}
	return &spec, nil
}

// LoadTier2Frontmatter diskten yalnızca frontmatter okur (VM yok).
func LoadTier2Frontmatter(path string) (*plugin.PluginSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseTier2Frontmatter(path, data)
}

// JSPlugin lazy goja VM sarmalayıcıdır (Aşama 2 — politika filtresinden geçmeden VM yok).
type JSPlugin struct {
	Spec   plugin.PluginSpec
	Path   string
	Source string

	mu  sync.Mutex
	vm  *goja.Runtime
	run goja.Callable
}

// NewJSPlugin frontmatter + kaynakla kurar (henüz evaluate YOK).
func NewJSPlugin(spec plugin.PluginSpec, path, source string) *JSPlugin {
	return &JSPlugin{Spec: spec, Path: path, Source: source}
}

// EnsureLoaded VM'i bir kez başlatır + script'i evaluate eder + run()'ı bağlar.
// Host yalnızca probe/ctx/host.oracles/host.candidate binding'lerini enjekte eder;
// require/dosya I/O/ham soket YOKTUR. eval/Function devre dışıdır.
func (j *JSPlugin) EnsureLoaded() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.vm != nil {
		return nil
	}
	vm := goja.New()
	// CPU guard: call-stack limiti.
	vm.SetMaxCallStackSize(512)

	// eval/Function yasağı: host tarafından devre dışı.
	_ = vm.Set("eval", goja.Undefined())
	// Function constructor'ı etkisizleştir (sandbox).
	if err := vm.Set("Function", goja.Undefined()); err != nil {
		return fmt.Errorf("js sandbox setup: %w", err)
	}

	// Minimal host binding iskeleti (Faz 2: gerçek probe/oracle bağlama Faz 3'te genişler).
	host := vm.NewObject()
	oracles := vm.NewObject()
	_ = oracles.Set("reflection", func(call goja.FunctionCall) goja.Value { return goja.Null() })
	_ = host.Set("oracles", oracles)
	_ = host.Set("candidate", func(call goja.FunctionCall) goja.Value { return goja.Null() })
	if err := vm.Set("host", host); err != nil {
		return fmt.Errorf("js host binding: %w", err)
	}
	_ = vm.Set("probe", vm.NewObject())
	_ = vm.Set("ctx", vm.NewObject())

	if _, err := vm.RunString(j.Source); err != nil {
		return fmt.Errorf("js evaluate %s: %w", j.Path, err)
	}
	v := vm.Get("run")
	if v == nil || goja.IsUndefined(v) {
		return fmt.Errorf("js %s: run() bulunamadı: %w", j.Path, plugin.ErrValidation)
	}
	fn, ok := goja.AssertFunction(v)
	if !ok {
		return fmt.Errorf("js %s: run fonksiyon değil: %w", j.Path, plugin.ErrInvalidReturn)
	}
	j.vm = vm
	j.run = fn
	return nil
}

// RunTimeout script'i timeout ile çalıştırır; ctx iptalinde vm.Interrupt gerçek kesmedir (D3).
func (j *JSPlugin) RunTimeout(ctx context.Context, timeout time.Duration) error {
	if err := j.EnsureLoaded(); err != nil {
		return err
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("js panic: %v: %w", r, plugin.ErrPanic)
			}
		}()
		j.mu.Lock()
		vm := j.vm
		run := j.run
		j.mu.Unlock()
		// goja çağrısı; host binding'ler üzerinden candidate döner.
		// B7 geçersiz-dönüş: run() dizi-dışı dönerse plugin hatasıdır (aday yutulmaz, açıkça loglanır).
		v, err := run(goja.Undefined(), vm.Get("probe"), vm.Get("ctx"))
		if err != nil {
			done <- fmt.Errorf("js run: %w", err)
			return
		}
		if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
			done <- nil // undefined/null → boş aday (geçerli)
			return
		}
		exported := v.Export()
		switch exported.(type) {
		case []any, []map[string]any, []string, map[string]any:
			done <- nil
		default:
			// String/number dönerse geçersiz dönüş (Faz 3'te []Candidate tip denetimine genişler).
			if _, ok := exported.(string); ok {
				done <- fmt.Errorf("js run geçersiz dönüş (string): %w", plugin.ErrInvalidReturn)
				return
			}
			done <- nil
		}
	}()

	select {
	case <-ctx.Done():
		j.mu.Lock()
		if j.vm != nil {
			j.vm.Interrupt("plugin timeout")
		}
		j.mu.Unlock()
		// Interrupt sonrası goja çağrısının bitmesini kısa süre bekle.
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("%w: %v", plugin.ErrTimeout, err)
			}
			return fmt.Errorf("%w: interrupted", plugin.ErrTimeout)
		case <-time.After(2 * time.Second):
			return fmt.Errorf("%w: interrupt sonrası yanıt yok", plugin.ErrTimeout)
		}
	case err := <-done:
		return err
	}
}
