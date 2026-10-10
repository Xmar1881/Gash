# GASH hybrid worker

This directory contains the optional Go worker used by GASH 0.6.0. Python
remains the policy and verdict owner; the worker only performs bounded ranking
or fetch work and returns JSON. If the binary is unavailable, GASH falls back
to the Python path.

## Build and verify

```bash
go vet ./...
go test ./...
go build -o bin/gash-worker .
```

From the repository root, enable it with:

```bash
py gash.py -t https://target.example --full --go-worker
```

The worker is opt-in. Proxy, `--insecure`, and request pacing keep the Python
transport path so the scan policy is not bypassed.

## Wire protocol

- Default mode reads one JSON `Job` from stdin and writes one JSON `Result`.
- `--stream` reads newline-delimited JSON jobs and emits one result per line.
- Supported jobs are `ping`, `tech-fingerprint`, `rank-wordlist`,
  `prioritize-urls`, and bounded `fetch-batch`.
- Malformed stream lines produce an error result and do not wedge the worker.
- No payload execution, exploit chain, session storage, or autonomous verdict
  promotion occurs in Go.

The wire types live in `protocol.go`; the Python adapter and fallback are in
`../core/goworker.py`.
