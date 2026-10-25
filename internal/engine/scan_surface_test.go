// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors

package engine

import (
	"fmt"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

func TestPluginSurfacePointsBoundsTier2Fanout(t *testing.T) {
	cfg := DefaultConfig()
	spec := plugin.PluginSpec{Tier: plugin.TierJS}
	points := make([]loader.JSPoint, 0, 40)
	for i := 0; i < 40; i++ {
		points = append(points, loader.JSPoint{
			URL:           fmt.Sprintf("https://example.test/page-%d", i),
			Method:        "GET",
			ParamName:     "q",
			ParamLocation: "query",
		})
	}
	// An observed form point must outrank the long tail of parameterless
	// endpoints because it carries a higher-value injection context.
	points = append(points, loader.JSPoint{
		URL:           "https://example.test/account",
		Method:        "POST",
		ParamName:     "email",
		ParamLocation: "body",
		FormValues:    map[string]string{"email": "user@example.test"},
	})
	points = append(points, points[0])

	got := pluginSurfacePoints(cfg, spec, points)
	if len(got) != 16 {
		t.Fatalf("tier2 surface cap = %d, want 16", len(got))
	}
	if got[0].URL != "https://example.test/account" {
		t.Fatalf("high-value form point was not prioritized: %+v", got[0])
	}
	for i := range got {
		for j := i + 1; j < len(got); j++ {
			if got[i].URL == got[j].URL && got[i].ParamName == got[j].ParamName && got[i].Method == got[j].Method {
				t.Fatalf("duplicate surface point at %d and %d: %+v", i, j, got[i])
			}
		}
	}
}

func TestPluginSurfacePointsLeavesTier1SurfaceUnchanged(t *testing.T) {
	cfg := DefaultConfig()
	spec := plugin.PluginSpec{Tier: plugin.TierYAML}
	points := []loader.JSPoint{{URL: "https://example.test/", Method: "GET"}}
	got := pluginSurfacePoints(cfg, spec, points)
	if len(got) != len(points) || got[0].URL != points[0].URL {
		t.Fatalf("tier1 surface must remain unchanged: got %+v", got)
	}
}
