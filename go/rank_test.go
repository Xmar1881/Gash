package main

// Fixture parity: the same vectors in testdata/ are asserted by the Python
// fallback tests (tests/test_goworker.py), so Go and Python can never drift.

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func loadFixture(t *testing.T, name string) (map[string]any, []string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Input    map[string]any `json:"input"`
		Expected []string       `json:"expected"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Input, doc.Expected
}

func strList(v any) []string {
	out := []string{}
	if arr, ok := v.([]any); ok {
		for _, e := range arr {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func TestRankWordlistFixture(t *testing.T) {
	in, expected := loadFixture(t, "rank_wordlist.json")
	limit := 0
	if f, ok := in["limit"].(float64); ok {
		limit = int(f)
	}
	got := rankWordlist(strList(in["techs"]), strList(in["paths"]), limit)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("rankWordlist = %v, want %v", got, expected)
	}
}

func TestPrioritizeURLsFixture(t *testing.T) {
	in, expected := loadFixture(t, "prioritize_urls.json")
	limit := 0
	if f, ok := in["limit"].(float64); ok {
		limit = int(f)
	}
	got := prioritizeURLs(strList(in["urls"]), limit)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("prioritizeURLs = %v, want %v", got, expected)
	}
}
