# Hybrid scoreboard (stdlib lab)

Python engine vs Go worker (`--go-worker`): same verdicts, faster fetching. One row per check: vulnerable endpoint must fire (TP), fixed twin must stay below MEDIUM (FP).

| check | TP py/go | FP py/go | parity |
|---|---|---|---|
| xss-reflected | ✅/✅ | 0/0 | ✅ |
| xss-stored | ✅/✅ | 0/0 | ✅ |
| sqli-error | ✅/✅ | 0/0 | ✅ |
| sqli-blind | ✅/✅ | 0/0 | ✅ |
| ssrf-surface | ✅/✅ | 0/0 | ✅ |
| idor-path | ✅/✅ | 0/0 | ✅ |
| login-enum | ✅/✅ | 0/0 | ✅ |
| upload-form | ✅/✅ | 0/0 | ✅ |
| proto-surface | ✅/✅ | 0/0 | ✅ |

recall: 9/9, false positives: 0, parity: 9/9

speed, corrected: earlier 0.55s -> 0.05s claims came from an
in-process lab server sharing the GIL with the measured
client (punished Python threads only). Against an isolated
server both engines tie on localhost; `py
bench/latency_curve.py` (separate-process lab, parity `same`
in every cell):

| injected RTT | python | go-worker |
|---|---|---|
| 0ms | ~0.05s | ~0.12s |
| 25ms | ~0.18s | ~0.18s |
| 100ms | ~0.54s | ~0.64s |

reading: no repeatable large speedup on equal footing — both
engines are latency-bound and the gap is process/pipe
overhead either way. The hybrid's durable value is parity +
offloaded fan-out (one spawn per scan via --stream) + a
single-binary fetch path, not a multiplier. The persistent
worker stays: it removes per-batch spawn cost regardless.
