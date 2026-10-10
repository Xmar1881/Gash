// gash-worker: Go side of the Python+Go hybrid engine.
//
// Protocol: Job JSON on stdin, Result JSON on stdout. No state.
// The Python bridge (core/goworker.py) spawns this binary per job batch,
// parses stdout, and maps results back (GoFinding -> core.scanner.Finding,
// fetch heads -> Python verdicts).
//
// One file per job family (same pattern as core/scan, core/deep, core/checks):
//   protocol.go -> wire types (Job/Result/FetchReq/FetchRes/GoFinding)
//   tech.go     -> tech-fingerprint (offline markers)
//   rank.go      -> rank-wordlist, prioritize-urls (pure ordering)
//   fetch.go     -> fetch-batch (bounded concurrent GETs, fetch-only)
//   stream.go    -> --stream loop (persistent worker, NDJSON)
//   main.go      -> dispatch (run) + entry point
//
// Jobs:
//   ping, tech-fingerprint (offline) / rank-wordlist, prioritize-urls
//   (pure ranking) / fetch-batch (bounded I/O; verdicts stay in Python)
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func handlePing(job Job) Result {
	return Result{OK: true, Job: job.Job, Findings: []GoFinding{}, Pong: true}
}

func run(job Job) Result {
	switch job.Job {
	case "ping":
		return handlePing(job)
	case "tech-fingerprint":
		return handleTechFingerprint(job)
	case "rank-wordlist":
		return Result{OK: true, Job: job.Job, Findings: []GoFinding{},
			Paths: rankWordlist(job.Techs, job.Paths, job.Limit)}
	case "prioritize-urls":
		return Result{OK: true, Job: job.Job, Findings: []GoFinding{},
			URLs: prioritizeURLs(job.URLs, job.Limit)}
	case "fetch-batch":
		fetches, errStr := fetchBatch(job)
		if errStr != "" {
			return Result{OK: false, Job: job.Job, Error: errStr}
		}
		return Result{OK: true, Job: job.Job, Findings: []GoFinding{},
			Fetches: fetches}
	default:
		return Result{OK: false, Job: job.Job, Error: "unknown job: " + job.Job}
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--stream" {
		runLoop(bufio.NewReader(os.Stdin), bufio.NewWriter(os.Stdout))
		return
	}
	var job Job
	if err := json.NewDecoder(os.Stdin).Decode(&job); err != nil {
		out, _ := json.Marshal(Result{OK: false, Error: "bad job JSON: " + err.Error()})
		fmt.Println(string(out))
		os.Exit(0)
	}
	res := run(job)
	if res.Findings == nil {
		res.Findings = []GoFinding{}
	}
	out, err := json.Marshal(res)
	if err != nil {
		fmt.Println(`{"ok":false,"error":"encode failed"}`)
		os.Exit(0)
	}
	fmt.Println(string(out))
}
