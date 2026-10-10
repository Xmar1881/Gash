package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStreamLoopServesMany(t *testing.T) {
	var stdin bytes.Buffer
	for _, job := range []string{
		`{"job":"ping"}`,
		`{"job":"rank-wordlist","techs":["php"],"paths":["a","x.php"],"limit":10}`,
		`{"job":"nope"}`,
		`not json at all`,
		`{"job":"prioritize-urls","urls":["http://h/a","http://h/?x=1"],"limit":10}`,
	} {
		stdin.WriteString(job + "\n")
	}
	var stdout bytes.Buffer
	runLoop(bufio.NewReader(&stdin), bufio.NewWriter(&stdout))

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("want 5 result lines, got %d: %q", len(lines), stdout.String())
	}
	var rs []map[string]any
	for _, ln := range lines {
		var r map[string]any
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("line is not JSON: %q", ln)
		}
		rs = append(rs, r)
	}
	if rs[0]["pong"] != true {
		t.Fatalf("ping failed: %v", rs[0])
	}
	paths, _ := rs[1]["paths"].([]any)
	if len(paths) != 2 || paths[0] != "x.php" {
		t.Fatalf("rank wrong: %v", rs[1])
	}
	if rs[2]["ok"] != false {
		t.Fatalf("unknown job must fail: %v", rs[2])
	}
	if rs[3]["ok"] != false {
		t.Fatalf("bad JSON must fail open with error: %v", rs[3])
	}
	urls, _ := rs[4]["urls"].([]any)
	if len(urls) != 2 || urls[0] != "http://h/?x=1" {
		t.Fatalf("prioritize wrong: %v", rs[4])
	}
}

func TestStreamLoopEmptyCloses(t *testing.T) {
	var stdout bytes.Buffer
	runLoop(bufio.NewReader(bytes.NewReader(nil)), bufio.NewWriter(&stdout))
	if stdout.Len() != 0 {
		t.Fatalf("empty stdin must produce no output, got %q", stdout.String())
	}
}
