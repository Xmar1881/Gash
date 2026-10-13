<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: templates/README.md
What: Minimal copy-rename starter for community plugins.
Why: Keeps the template repo note inside the main repository.
-->

# Plugin Templates

## Purpose

Minimal Tier 1 and Tier 2 starters that already pass `validate` and `test`.
Copy one file plus its fixture directory, rename the `id`, and start editing.

## Contents

- `template.yaml`: Tier 1 header starter (`id: template-yaml`).
- `template.js`: Tier 2 reflection starter (`id: template-js`).
- `tests/fixtures/template-yaml/`: one positive plus two negatives.
- `tests/fixtures/template-js/`: one positive plus two negatives.

## Usage

```sh
cp templates/template.yaml my-check.yaml
cp -r templates/tests/fixtures/template-yaml tests/fixtures/my-check
# Edit id, name, description in my-check.yaml to match my-check.
go run ./cmd/gash plugins validate my-check.yaml
go run ./cmd/gash plugins test my-check.yaml
```

Prefer the generator for new names; it writes the same shape with the
correct `id` and `tests` pointer:

```sh
go run ./cmd/gash plugins new my-check --tier yaml
go run ./cmd/gash plugins new my-xss --tier js
```

## Template Repo Note

These files double as the standalone template repository seed. A minimal
external repo needs only `template.yaml`, `template.js`, the two fixture
trees, this README, and a copy of `CONTRIBUTING.md` plus the tier guides.
No engine code is required; `plugin-ci.yml` validates the fork the same way
it validates this repository.
