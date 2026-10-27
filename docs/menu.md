<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash
-->

# Interactive menu

The menu is the default operator surface for Gash. It wraps every command in a
guided flow, keeps a live status panel next to the scan controls, and can run
any CLI command without leaving the terminal.

```sh
gash menu
# or simply start gash without arguments in a terminal
```

The interface is Turkish by default. Use `gash menu --lang en`, `GASH_LANG=en`,
or press `l` inside the menu to switch to English. The choice applies to the
current session.

## Layout

The main screen uses a compact operator chrome:

```text
  ◆ GASH  v0.1.0-dev                                   TR · 6 sekme
  hibrit plugin güvenlik tarayıcısı
  ⚠ Yasal uyarı · Yalnızca sahibi olduğunuz veya yazılı izin
    aldığınız hedeflerde kullanın.

  GASH › ◎ Tarama                                           TR · 1/6
  ──────────────────────────────────────────────────────────────
   ▸ 1 Tarama   2 Pluginler   3 Araçlar   4 Konsol   5 Durum   6 Yardım

  ╭─ ◎ Tarama ──────────────────────────────────────────────────╮
  │ Hedef URL tarama ve profil seçimi                           │
  │                                                             │
  │ › Profiller: safe · standard · deep · aggressive · HER ŞEY  │
  │ › HER ŞEY: agresif + tarayıcı + altyapı + OOB tek seçimde   │
  │                                                             │
  │  Enter ↵  ile aç  ·  sekme numarası veya kısayol harfi       │
  ╰─────────────────────────────────────────────────────────────╯
  ──────────────────────────────────────────────────────────────
  [1-6] sekme · Enter aç · n/< gezin · l dil · :komut · h yardım · q çıkış
  gash menü ❯
```

- The top bar keeps the brand, build, language, and tab position visible.
- Tabs are numbered segments; the active tab is highlighted and every tab also
  has a single-letter alias (`s`, `p`, `t`, `c`, `u`, `h`). The specialized
  tools live under **Tools**: `b` benchmark, `o` OpenAPI, `d` diff, `x`
  suppress jump straight into that tool.
- The content card carries the tab description, details, and the primary
  `Enter` action; the footer keeps the key map and the last command result.
- The prompt turns green after a successful command and red after a failure.
- The layout is width-aware and falls back to plain text when output is piped
  or `NO_COLOR` is set.

## Navigation

| Key | Action |
|---|---|
| `1`–`6` | Open a tab by number |
| `s` `p` `t` `c` `u` `h` | Open a tab by shortcut letter |
| `b` `o` `d` `x` | Jump straight into benchmark / OpenAPI / diff / suppress |
| `Enter` | Open the highlighted tab |
| `n` / `<` | Move to the next / previous tab |
| `l` | Toggle Turkish / English |
| `r` | Repeat the last command with the same arguments |
| `:command` | Run a Gash command without leaving the menu (for example `:plugins list`) |
| `q` | Quit |
| `Ctrl+C` | Cancel the running command (the menu stays open) |

Tab names are aliases too: `scan`, `plugins`, `tools`, `durum`, `yardim`, and
their Turkish equivalents open the same screens. During any prompt, type
`iptal` (Turkish) or `cancel` to go back without changing anything.

## Tabs

| Tab | Shortcut | What it does |
|---|---|---|
| Tarama / Scan | `s`, `1` | Guided single-target or bulk scan, profile, proxy, auth, OOB, output |
| Pluginler / Plugins | `p`, `2` | List, inspect, validate, test, scaffold, and trust plugins |
| Araçlar / Tools | `t`, `3` | Benchmark, OpenAPI plan, report diff, suppressions (`b` `o` `d` `x`) |
| Konsol / Console | `c`, `4` | Full command console with history and `!!` replay |
| Durum / Status | `u`, `5` | Build, Chrome, Go, catalog, proxy list, and recent reports |
| Yardım / Help | `h`, `6` | Keyboard shortcuts and the live Cobra command list |

## Scan tab

The scan tab asks only for what the selected profile needs:

- **Target**: a URL, or a path to a file. A file switches to bulk mode: one
  target per line, `#` comments allowed, per-target same-site scope, an output
  directory, and an optional `--resume`.
- **Profile**: `safe`, `standard`, `deep`, `aggressive`, or the one-step
  **HER ŞEY** preset (aggressive + browser + infrastructure + OOB).
- **Scope**: empty means automatic same-site scope (the target's registrable
  domain). Use `--allow-external` to leave the domain, or an explicit scope to
  pin an allowlist.
- **Proxy mode**: `auto` loads the healthy list, `off` is direct traffic
  (`--no-proxy`), `single` asks for one upstream, and `all` uses the full pool
  with per-request rotation.
- **Auth mode**: `cookie`, `header`, or `login`. Login upgrades the profile to
  `standard` and enables `--active`; the password is read from an environment
  variable and never echoed.
- **OOB**: local listener, self-hosted interactsh, or a custom API. Public
  interactsh is never selected implicitly.

Before execution the menu prints a summary and the equivalent command. Secret
flags (`--cookie`, `--auth-header`, `--oob-token`, `--login-pass`,
`--basic-auth`) and proxy credentials are masked in both the preview and the
last-command history.

## Live scan detail

While a scan runs, every phase finishes with a frozen summary line (last detail
plus measured duration), while the phase currently running stays on the
spinner line. This keeps long phases answerable instead of showing one label
for minutes:

```text
✔ [Teknoloji Analizi] parmak izi tamam · 3 teknoloji · 5 yetenek (412ms)
✔ [Planlama] 338 plugin planlandı · 0 atlandı (1ms)
✔ [Protokol Denetimi] TLS/DNS tamam · 2 bulgu · 0 atlanan (1.4s)
✔ [Sayfa & Yüzey Keşfi] tamam · 50 sayfa · 140 yüzey · 52 istek · 3200 ms (3.2s)
⠹ [Güvenlik Testleri] 128/338 (xss-reflected-basic) (03:12)
```

The phase details come from the engine, not the menu: crawl gives page/surface
counts, JS recon gives files/endpoints/secrets, SPA gives state/dev-build
counts, content discovery gives requests/findings, fuzz stages give
points/requests/findings, plugin execution gives completed/total plus
partial/error counts, and correlation gives deduplicated findings. A skipped
phase says why (for example `atlandı: detector smuggle disabled by profile`).
All phase labels, detail templates, hints, and the completion line are
translated: switching to EN also switches the scan progress.

## Status tab

`u` (or `8`) shows the effective runtime state:

```text
╭─ Sistem durumu ─────────────────────────────────────────────╮
│ Build          deep (chromedp)                              │
│ Chrome         C:\Program Files\Google\Chrome\...\chrome.exe│
│ Go             go1.27.3 · windows/amd64                     │
│ Katalog        338 plugin                                   │
│ Proxy          ...\.gash\proxies\alive.txt (101)            │
│ Raporlar       5                                            │
╰─────────────────────────────────────────────────────────────╯
```

Actions: `r` refresh, `o` open the reports directory, `v` view the latest text
report, `p` print the proxy health-check command, `0` back.

## Console tab

`c` opens a command console. Type commands without the `gash` prefix:

```text
gash ❯ plugins list
gash ❯ scan --target http://localhost:8080 --scope localhost
gash ❯ !!
```

`history` lists recent commands (secrets are redacted), `!!` repeats the last
one, `!N` runs entry N, `clear` clears the screen, `?` prints full help, and
`menu` returns to the tab view. `:command` does the same from the main prompt.

## Non-interactive use

Every menu action maps to a documented CLI flag, so anything you do in the menu
can be scripted:

```sh
gash scan --target https://app.example.com --profile standard \
  --proxy-file .gash/proxies/alive.txt --proxy-rotate per-host \
  --format json --format text --output-dir reports
```

See [user-guide-tr.md](user-guide-tr.md) for Turkish walkthroughs and
[getting-started.md](getting-started.md) for the CLI-first tutorial.
