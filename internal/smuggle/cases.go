// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/smuggle/cases.go
// What: Embedded differential case table for the raw-TCP smuggling probe.
// Why: The desynchronization axes are data (cases.yaml), so extending the probe
// is a table edit instead of control-flow surgery. The loader fails closed on a
// malformed table, and the golden-byte test pins the emitted wire format.

package smuggle

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Case is one differential framing axis.
// What: Header framing plus the harmless body terminator for one kind.
// Why: Everything the probe needs to emit an ambiguous first request is here,
// so the code that writes bytes stays a single, auditable builder.
type Case struct {
	// Kind is the human-readable axis name (CL.TE, TE.CL, TE.TE).
	Kind string `yaml:"kind"`
	// Name explains the desynchronization this axis exercises.
	Name string `yaml:"name"`
	// ContentLength is the declared Content-Length value.
	ContentLength int `yaml:"content_length"`
	// TransferEncoding lists the Transfer-Encoding header lines in order; more
	// than one entry means the header is duplicated (the TE.TE axis).
	TransferEncoding []string `yaml:"transfer_encoding"`
	// Body is the harmless chunk terminator written after the headers.
	Body string `yaml:"body"`
}

// caseFile is the YAML document shape.
type caseFile struct {
	Cases []Case `yaml:"cases"`
}

// casesYAML is the embedded case table (compile-time data).
//
//go:embed cases.yaml
var casesYAML []byte

// declaredCases is the validated table, loaded once at package init.
var declaredCases = mustLoadCases()

// mustLoadCases parses and validates the embedded table.
// What: Fail-closed loading of compile-time data.
// Why: A malformed case table would silently change what the probe sends; the
// embedded file is a build artifact, so a defect must fail loudly and early.
func mustLoadCases() []Case {
	var cf caseFile
	if err := yaml.Unmarshal(casesYAML, &cf); err != nil {
		panic(fmt.Sprintf("smuggle: case table parse: %v", err))
	}
	if len(cf.Cases) == 0 {
		panic("smuggle: case table is empty")
	}
	seen := make(map[string]bool, len(cf.Cases))
	for i, c := range cf.Cases {
		switch {
		case strings.TrimSpace(c.Kind) == "":
			panic(fmt.Sprintf("smuggle: case %d has no kind", i))
		case seen[c.Kind]:
			panic(fmt.Sprintf("smuggle: duplicate case kind %q", c.Kind))
		case c.ContentLength <= 0:
			panic(fmt.Sprintf("smuggle: case %q has no content length", c.Kind))
		case len(c.TransferEncoding) == 0:
			panic(fmt.Sprintf("smuggle: case %q has no transfer encoding", c.Kind))
		case c.Body == "":
			panic(fmt.Sprintf("smuggle: case %q has no body", c.Kind))
		}
		seen[c.Kind] = true
	}
	return cf.Cases
}

// Cases returns the declared cases in table order.
// What: Copy of the validated table for tests, docs, and reporting.
// Why: Callers must not be able to mutate the package's probe definition.
func Cases() []Case {
	out := make([]Case, len(declaredCases))
	copy(out, declaredCases)
	return out
}

// caseFor returns the case with the given kind.
// What: Kind lookup for the ambiguous-request builder.
// Why: An unknown kind must fall back to the declared default (first case)
// instead of silently emitting an unframed request.
func caseFor(kind string) Case {
	for _, c := range declaredCases {
		if c.Kind == kind {
			return c
		}
	}
	return declaredCases[0]
}
