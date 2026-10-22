# Gash

**Evidence-first web security scanner for teams that care about signal, explainability, and controlled execution.**

> "Plugins propose candidates; engine-owned oracles decide whether those candidates deserve to become findings."

---

## 🎯 Why Gash?

| Problem | Gash Approach |
|---------|---------------|
| Scanner noise (false positives) | **Proof chains**: every finding carries `confirmed`/`firm`/`tentative` evidence with control comparison |
| Black-box results | **Explainable findings**: source→sink traces, oracle decisions, control results in JSON/SARIF/HTML |
| Uncontrolled execution | **Safe defaults**: passive by default; active/OOB requires explicit `--active` + `--oob-server` |
| Scope creep | **Strict allowlist**: `--scope` CIDR/domain with DNS rebinding pinning |
| Untestable plugins | **Fixture-driven**: 200+ positive/negative/ambiguous test cases per plugin class |

---

## 🚀 Quick Start

```bash
# Install (Linux/macOS/Windows)
go install github.com/Xmar1881/Gash/cmd/gash@latest

# Scan a target you own
gash scan --target https://example.com --profile standard

# Deep scan with browser verification (requires Chrome)
gash scan --target https://example.com --profile deep --browser-verify
```

## 📦 Installation Options

| Method | Command |
|--------|---------|
| **Go install** | `go install github.com/Xmar1881/Gash/cmd/gash@latest` |
| **Homebrew** | `brew tap xmar1881/gash && brew install gash` *(coming soon)* |
| **Scoop** | `scoop bucket add gash https://github.com/Xmar1881/scoop-gash && scoop install gash` *(coming soon)* |
| **Docker** | `docker run --rm ghcr.io/xmar1881/gash:latest scan --target ...` *(coming soon)* |
| **Binary** | [GitHub Releases](https://github.com/Xmar1881/Gash/releases) |

## 🔬 Detectors (75+)

| Class | Plugins | Oracle | Confidence |
|-------|---------|--------|------------|
| XSS (reflected/stored/DOM) | 15+ | `reflection`, `stored`, `execution` | tentative → confirmed |
| SQL Injection | 12+ | `error`, `differential`, `timing`, `oob` | firm → confirmed |
| Command Injection | 4 | `error`, `timing`, `oob` | firm → confirmed |
| Path Traversal | 3 | `error` | firm → confirmed |
| SSRF / Open Redirect | 6 | `redirect`, `oob` | firm → confirmed |
| NoSQL / LDAP / SSTI | 5 | `timing`, `differential`, `oob` | firm → confirmed |
| GraphQL (auth bypass, DoS) | 3 | `differential` | firm |
| Auth/IDOR/BOLA | 4 | `differential` | confirmed |
| Info Disclosure | 15+ | `error`, `header`, `version` | firm → confirmed |
| Proto Recon (TLS/DNS/SSH/DB) | 8 | `tls`, `dns`, `ssh`, `db` | tentative → confirmed |

[Full Detector Inventory →](https://github.com/Xmar1881/Gash/blob/main/docs/detector-inventory.md)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      ENGINE (Go)                            │
│  Crawler → Surface Extraction → Plugin Execution → Oracles │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   ┌─────────┐           ┌─────────┐           ┌─────────┐
   │ Tier 1  │           │ Tier 2  │           │ Tier 3  │
   │ YAML    │           │ JS      │           │ gRPC    │
   │ (decl.) │           │ (sand.) │           │ (trust) │
   └─────────┘           └─────────┘           └─────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌─────────────────┐
                    │ Engine Oracles  │
                    │ (reflection,    │
                    │  error, diff,   │
                    │  timing, oob,   │
                    │  execution...)  │
                    └─────────────────┘
```

---

## 📊 Benchmarks

| Profile | Scenarios | Precision | Recall | F1 | Duration |
|---------|-----------|-----------|--------|-----|----------|
| Standard | 50 | 1.000 | 1.000 | 1.000 | ~1m30s |
| Deep | 50 | 1.000 | 1.000 | 1.000 | ~7m |

[Benchmark Details →](https://github.com/Xmar1881/Gash/blob/main/docs/benchmark.md)

---

## 🤝 Contributing

We welcome plugin contributions! See [CONTRIBUTING.md](https://github.com/Xmar1881/Gash/blob/main/CONTRIBUTING.md) for:
- Plugin development guide (Tier 1/2/3)
- Fixture test requirements
- Evidence standards
- CI gates

**Good first plugins**: Check `plugins/README.md` for "Good First Contribution" labels.

---

## 📚 Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](https://github.com/Xmar1881/Gash/blob/main/docs/getting-started.md) | Narrative tutorial |
| [Plugin Development](https://github.com/Xmar1881/Gash/blob/main/docs/plugin-development.md) | Write your own detectors |
| [Evidence Standard](https://github.com/Xmar1881/Gash/blob/main/docs/evidence-standard.md) | Proof rules per class |
| [Known Limits](https://github.com/Xmar1881/Gash/blob/main/docs/known-limits.md) | Honest BLOCKED register |
| [CI Integration](https://github.com/Xmar1881/Gash/blob/main/docs/ci-integration.md) | Fail-on gates, SARIF |

---

## 🛡️ Security & Responsible Use

- **Security Policy**: [.github/SECURITY.md](https://github.com/Xmar1881/Gash/blob/main/.github/SECURITY.md)
- **License**: AGPL-3.0-only — source available, no commercial dual-license
- **Scope Discipline**: Only scan targets you own or have written permission for
- **Legal**: Unauthorized scanning may be illegal in your jurisdiction

---

## 💬 Community & Support

- **GitHub Discussions**: [Ask questions, share findings](https://github.com/Xmar1881/Gash/discussions)
- **Discord**: [Join the community](https://discord.gg/gash) *(coming soon)*
- **Twitter/X**: [@GashScanner](https://twitter.com/GashScanner) *(coming soon)*
- **Issues**: [Bug reports & feature requests](https://github.com/Xmar1881/Gash/issues)

---

## 📄 License

AGPL-3.0-only — Copyright (C) 2026 Xmar1881 / Gash contributors

See [LICENSE](https://github.com/Xmar1881/Gash/blob/main/LICENSE) for full text.