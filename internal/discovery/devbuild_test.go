// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"strings"
	"testing"
)

func TestDetectDevBuildMarkers(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		marker string
	}{
		{"react dom development", `<script src="/_next/static/chunks/react-dom.development.js"></script>`, "react-dom.development.js"},
		{"react development", `import { jsx } from "react.development.js"`, "react.development.js"},
		{"jsx dev runtime", `return jsxDEV(type, props, key, false, true);`, "jsxDEV("},
		{"vue global dev", `<script src="https://cdn.test/vue.global.js"></script>`, "vue.global.js"},
		{"angular probe", `const el = ng.probe(document.querySelector('app-root'));`, "ng.probe("},
		{"angular getComponent", `ng.getComponent(document.querySelector('app-root'));`, "ng.getComponent("},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectDevBuildMarkers([]byte(tc.body))
			if len(got) == 0 {
				t.Fatalf("no marker found")
			}
			if got[0].Marker != tc.marker {
				t.Fatalf("marker %q want %q", got[0].Marker, tc.marker)
			}
			if got[0].Snippet == "" || len(got[0].Snippet) > 160 {
				t.Fatalf("bad snippet %q", got[0].Snippet)
			}
		})
	}
}

func TestDetectDevBuildMarkersRejectsProductionNoise(t *testing.T) {
	body := `<script>
window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || {};
window.__VUE_DEVTOOLS_GLOBAL_HOOK__ = window.__VUE_DEVTOOLS_GLOBAL_HOOK__ || {};
console.warn("warnings are not dev-build proof");
</script>
<script src="/_next/static/chunks/react-dom.production.min.js"></script>
<script src="https://cdn.test/vue.global.prod.js"></script>
<script src="/static/main.jsx"></script>`
	if got := DetectDevBuildMarkers([]byte(body)); len(got) != 0 {
		t.Fatalf("production noise must not match: %#v", got)
	}
}

func TestDevBuildSnippetMaskedAndBounded(t *testing.T) {
	long := strings.Repeat("a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0", 3)
	body := []byte(`ng.probe(el); const config = {"apiKey":"` + long + `"}; ` + strings.Repeat("x", 400))
	got := DetectDevBuildMarkers(body)
	if len(got) != 1 {
		t.Fatalf("want 1 marker, got %d", len(got))
	}
	if strings.Contains(got[0].Snippet, long) {
		t.Fatalf("long literal leaked unmasked: %q", got[0].Snippet)
	}
	if len(got[0].Snippet) > 160 {
		t.Fatalf("snippet too long: %d", len(got[0].Snippet))
	}
}

func TestDetectDevBuildMarkersSizeGuard(t *testing.T) {
	body := make([]byte, MaxJSAnalysisBytes+1)
	copy(body, []byte(`react-dom.development.js`))
	if got := DetectDevBuildMarkers(body); len(got) != 0 {
		t.Fatalf("oversize body must be ignored, got %d", len(got))
	}
}
