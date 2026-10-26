// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"encoding/json"
	"fmt"
)

// GenerateJSONSchema tek kural kaynağından JSON Schema 2020-12 üretir (A-09).
// Yön: rules.go → schema.json. El ile çift bakım YOKTUR.
func GenerateJSONSchema() ([]byte, error) {
	sev := make([]string, 0, len(ValidSeverities))
	for _, s := range ValidSeverities {
		sev = append(sev, string(s))
	}
	ph := make([]string, 0, len(ValidPhases))
	for _, p := range ValidPhases {
		ph = append(ph, string(p))
	}
	schema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     schemaID,
		"title":   "GASH PluginSpec v1.0",
		"type":    "object",
		"required": []string{
			"id", "name", "description", "severity", "tags", "safe", "deep",
			"active", "requires_auth", "phase", "order", "api_version",
		},
		"properties": map[string]any{
			"id":            map[string]any{"type": "string", "pattern": `^[a-z0-9]+(-[a-z0-9]+)*$`, "maxLength": maxIDLen},
			"name":          map[string]any{"type": "string", "minLength": minNameLen, "maxLength": maxNameLen},
			"description":   map[string]any{"type": "string", "minLength": minDescLen, "maxLength": maxDescLen},
			"author":        map[string]any{"type": "string"},
			"severity":      map[string]any{"type": "string", "enum": sev},
			"tags":          map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string", "pattern": `^[a-z0-9-]+$`}},
			"safe":          map[string]any{"type": "boolean"},
			"deep":          map[string]any{"type": "boolean"},
			"active":        map[string]any{"type": "boolean"},
			"requires_auth": map[string]any{"type": "boolean"},
			"requires_tech": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"max_requests":  map[string]any{"type": "integer", "minimum": minMaxRequests, "maximum": maxMaxRequests},
			"phase":         map[string]any{"type": "string", "enum": ph},
			"order":         map[string]any{"type": "integer", "minimum": minOrder, "maximum": maxOrder},
			"requires":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"provides":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"overrides":     map[string]any{"type": "string"},
			"oob":           map[string]any{"type": "string", "enum": []string{"", "optional", "required"}},
			"api_version":   map[string]any{"type": "string", "const": supportedAPIVer},
			"tests":         map[string]any{"type": "string"},
			"oracle_params": map[string]any{"type": "object"},
			"request": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"method":      map[string]any{"type": "string"},
					"param_names": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"payload":     map[string]any{"type": "string"},
				},
			},
			"oracle": map[string]any{
				"type":     "object",
				"required": []string{"name"},
				"properties": map[string]any{
					"name":   map[string]any{"type": "string"},
					"params": map[string]any{"type": "object"},
				},
			},
		},
		"allOf": []any{
			map[string]any{
				"if":   map[string]any{"properties": map[string]any{"safe": map[string]any{"const": true}}},
				"then": map[string]any{"properties": map[string]any{"active": map[string]any{"const": false}}},
			},
			map[string]any{
				"if":   map[string]any{"properties": map[string]any{"oob": map[string]any{"const": "required"}}},
				"then": map[string]any{"properties": map[string]any{"active": map[string]any{"const": true}}},
			},
		},
		"not": map[string]any{
			"anyOf": []any{
				map[string]any{"required": []string{"script"}},
				map[string]any{"required": []string{"code"}},
				map[string]any{"required": []string{"eval"}},
			},
		},
	}
	b, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("schema marshal: %w", err)
	}
	return append(b, '\n'), nil
}
