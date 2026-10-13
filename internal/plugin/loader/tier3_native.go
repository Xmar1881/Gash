// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
	"gopkg.in/yaml.v3"
)

// Tier3Manifest ayrı manifest dosyasıdır (.gashplugin.yaml). Binary'ye dokunulmaz.
// Faz 2'de process spawn YOKTUR — yalnızca registry + trust kapısı (B10).
type Tier3Manifest struct {
	plugin.PluginSpec `yaml:",inline"`
	Binary            string `yaml:"binary"`
	Protocol          string `yaml:"protocol"`
	SHA256            string `yaml:"sha256"`
	// Oracle declares the primary oracle for offline fixture tests.
	Oracle string `yaml:"oracle,omitempty"`
}

// ParseTier3Manifest manifesti parse eder (exec yok).
func ParseTier3Manifest(path string, data []byte) (*plugin.PluginSpec, *Tier3Manifest, error) {
	var m Tier3Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, nil, fmt.Errorf("tier3 manifest decode %s: %w", path, err)
	}
	m.Tier = plugin.TierNative
	if err := plugin.Validate(m.PluginSpec); err != nil {
		return nil, nil, fmt.Errorf("tier3 validate %s: %w", path, err)
	}
	if m.Binary == "" {
		return nil, nil, fmt.Errorf("tier3 %s: binary zorunlu: %w", path, plugin.ErrValidation)
	}
	if m.Protocol != "grpc" {
		return nil, nil, fmt.Errorf("tier3 %s: protocol yalnızca grpc (got %q): %w", path, m.Protocol, plugin.ErrValidation)
	}
	if m.SHA256 == "" {
		return nil, nil, fmt.Errorf("tier3 %s: sha256 pin zorunlu: %w", path, plugin.ErrValidation)
	}
	if err := plugin.CheckOOBOracle("", m.PluginSpec.OOB, m.PluginSpec.ID); err != nil {
		// oracle adı manifestte yoksa genel R-02/R-03 zaten Validate'te; burada ek yok.
		_ = err
	}
	return &m.PluginSpec, &m, nil
}

// LoadTier3Manifest diskten okur (binary çalıştırılmaz).
func LoadTier3Manifest(path string) (*plugin.PluginSpec, *Tier3Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseTier3Manifest(path, data)
}

// VerifySHA256 binary'nin sha256 pinini doğrular (trust kapısı).
func VerifySHA256(binaryPath, pinned string) error {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("tier3 sha256 read %s: %w", binaryPath, err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, strings.TrimSpace(pinned)) {
		return fmt.Errorf("tier3 sha256 uyuşmazlığı %s: %w", binaryPath, plugin.ErrTrustRequired)
	}
	return nil
}

// CheckTrust trust'suz asla çalıştırılmaz (B10). trustDB: manifest path → pinned sha.
// Faz 2'de spawn olmadığı için bu fonksiyon yalnızca "çalıştırılabilir mi" kararı verir.
func CheckTrust(m *Tier3Manifest, trustDB map[string]string) error {
	pinned, ok := trustDB[m.ID]
	if !ok {
		return fmt.Errorf("tier3 %s trust yok (gash plugins trust gerekli): %w", m.ID, plugin.ErrTrustRequired)
	}
	if !strings.EqualFold(strings.TrimSpace(pinned), strings.TrimSpace(m.SHA256)) {
		return fmt.Errorf("tier3 %s pin uyuşmazlığı: %w", m.ID, plugin.ErrTrustRequired)
	}
	return nil
}
