package main

import "strings"

// rankWordlist orders a candidate pool: tech-matching paths first (stable),
// then the rest in input order. Deduplicated, capped. Data (paths) arrives
// from Python; only the ordering rule lives here, so nothing can drift.
// The Python fallback in core/goworker.py mirrors this exactly; both sides
// are pinned by go/testdata/rank_wordlist.json.
func rankWordlist(techs []string, paths []string, limit int) []string {
	if limit <= 0 {
		limit = 80
	}
	low := make([]string, 0, len(techs))
	for _, t := range techs {
		if s := strings.ToLower(strings.TrimSpace(t)); s != "" {
			low = append(low, s)
		}
	}
	seen := map[string]bool{}
	hit := []string{}
	rest := []string{}
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		pl := strings.ToLower(p)
		matched := false
		for _, t := range low {
			if strings.Contains(pl, t) {
				matched = true
				break
			}
		}
		if matched {
			hit = append(hit, p)
		} else {
			rest = append(rest, p)
		}
	}
	out := append(hit, rest...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// prioritizeURLs orders a probe pool: query-bearing URLs first (stable),
// then the rest in input order. Deduplicated, capped. Mirrored by the
// Python fallback; pinned by go/testdata/prioritize_urls.json.
func prioritizeURLs(urls []string, limit int) []string {
	if limit <= 0 {
		limit = 25
	}
	seen := map[string]bool{}
	withQuery := []string{}
	plain := []string{}
	for _, u := range urls {
		if seen[u] {
			continue
		}
		seen[u] = true
		if strings.Contains(u, "?") {
			withQuery = append(withQuery, u)
		} else {
			plain = append(plain, u)
		}
	}
	out := append(withQuery, plain...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
