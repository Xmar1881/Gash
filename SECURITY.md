# Security Policy

## Authorized testing only

GASH is built for **authorized security testing**: your own systems, or systems
you have explicit written permission to test. Unauthorized scanning may be
illegal. You are responsible for how you use this tool.

## Safe defaults

Default scans avoid state-changing probes (no time-based delays, no active
POST submissions, no upload/login attempts). Aggressive checks require an
explicit opt-in (`--deep`). The interactive wizard (`--menu`) explains this
before every scan.

OOB callbacks (`--oob`) send probe URLs to an interactsh server (default:
public `interact.sh`). Use `--oob-server` with a self-hosted instance for
sensitive targets.

## Reporting a vulnerability in GASH itself

If you find a security issue in this repository (not in a third-party target),
please open a GitHub issue with `[SECURITY]` in the title and avoid posting
exploit details publicly until it is addressed.
