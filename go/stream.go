package main

import (
	"bufio"
	"encoding/json"
	"strings"
)

// runLoop serves NDJSON jobs until EOF: one Result line per Job line.
// This is the persistent-worker mode (--stream): Python keeps one process
// and amortizes the ~25ms spawn over the whole scan. Framing is
// line-based (not json.Decoder): a malformed line gets an error Result
// and can never wedge the stream, and the final line needs no trailing
// newline.
func runLoop(r *bufio.Reader, w *bufio.Writer) {
	enc := json.NewEncoder(w)
	answer := func(res Result) {
		if res.Findings == nil {
			res.Findings = []GoFinding{}
		}
		_ = enc.Encode(res)
		_ = w.Flush()
	}
	for {
		line, rerr := r.ReadString('\n')
		text := strings.TrimSpace(line)
		if text != "" {
			var job Job
			if uerr := json.Unmarshal([]byte(text), &job); uerr != nil {
				answer(Result{OK: false, Error: "bad job JSON: " + uerr.Error()})
			} else {
				answer(run(job))
			}
		}
		if rerr != nil {
			return // EOF (or a dead pipe): close the stream
		}
	}
}
