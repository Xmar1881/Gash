package bench

import "testing"

func TestVersionFromTextSkipsGoVersion(t *testing.T) {
	text := "WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU)\n[INF] Nuclei Engine Version: v3.11.1"
	if got := versionFromText(text, "nuclei"); got != "v3.11.1" {
		t.Fatalf("versionFromText = %q, want v3.11.1", got)
	}
	if got := versionFromText("Nuclei Engine Version: v3.11.1", "nuclei"); got != "v3.11.1" {
		t.Fatalf("versionFromText simple = %q", got)
	}
}
