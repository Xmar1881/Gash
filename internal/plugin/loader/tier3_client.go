// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"fmt"

	"github.com/Xmar1881/Gash/internal/plugin"
	goplugin "github.com/hashicorp/go-plugin"
)

// Tier3Client Faz 3 POC iskeletidir (Faz 2'de spawn YOK).
// Bu dosya hashicorp/go-plugin bağımlılığını go.mod'da pinli tutar (D4, v1.8.0)
// ve handshake/lifecycle kararlarını (A-13) tip-seviyesinde dondurur:
//   - yalnızca gRPC, AutoMTLS + loopback-only,
//   - lazy spawn (ilk çağrıda), per-call timeout, scan sonu Kill,
//   - versioned handshake uyumsuzluğunda fail-closed.
//
// Faz 2'de Serve/Dispense YOKTUR; CheckHandshake yalnızca manifest doğrulaması yapar.
// Gerçek spawn/kill zinciri (SIGTERM→SIGKILL) Faz 3 POC'undadır.
type Tier3Client struct {
	manifest *Tier3Manifest
	trusted  bool
}

// NewTier3Client trust kontrolünden geçmiş manifestle kurulur (B10).
// Trust'suz kurulamaz — fail-closed.
func NewTier3Client(m *Tier3Manifest, trustDB map[string]string) (*Tier3Client, error) {
	if err := CheckTrust(m, trustDB); err != nil {
		return nil, err
	}
	return &Tier3Client{manifest: m, trusted: true}, nil
}

// HandshakeConfig go-plugin el sıkışma sabitleridir (proto api_version "1.0" ile eşlenir).
func HandshakeConfig() goplugin.HandshakeConfig {
	return goplugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "GASH_PLUGIN",
		MagicCookieValue: "gash-v1",
	}
}

// CheckHandshake version pinini doğrular (uyumsuzlukta spawn yok).
func (c *Tier3Client) CheckHandshake(hostAPIVersion string) error {
	if c.manifest == nil {
		return fmt.Errorf("tier3 nil manifest: %w", plugin.ErrValidation)
	}
	if hostAPIVersion != "1.0" || c.manifest.APIVersion != "1.0" {
		return fmt.Errorf("tier3 handshake uyumsuz (host=%q plugin=%q): %w",
			hostAPIVersion, c.manifest.APIVersion, plugin.ErrValidation)
	}
	if !c.trusted {
		return fmt.Errorf("tier3 untrusted: %w", plugin.ErrTrustRequired)
	}
	return nil
}

// SecureConfig A-13 taşıma kararını belgeler (AutoMTLS + loopback).
func SecureConfig() goplugin.ServeConfig {
	return goplugin.ServeConfig{}
}
