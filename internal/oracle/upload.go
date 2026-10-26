// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// UploadServedParams models a file-upload workflow as TWO exchanges (GASH-038):
// request 1 uploads an artifact, request 2 fetches it back from the URL the
// server handed out. The decisive fact is not the HTML context of the fetched
// body — the reflection oracle already covers that — but the content type the
// server serves the artifact with: an executable payload inside a text/plain
// body never runs, while the same payload served as text/html or
// image/svg+xml does. A clean control URL (never uploaded to) proves the
// artifact is ours and not a pre-existing file.
type UploadServedParams struct {
	// Canary is the unique marker embedded in the uploaded artifact.
	Canary string
	// Exchange 1: the upload exchange.
	UploadStatus int
	UploadBody   string
	// Exchange 2: fetching the artifact back.
	FetchStatus  int
	FetchHeaders http.Header
	FetchBody    string
	// Control is the sibling URL that never received an upload.
	ControlStatus int
	ControlBody   string
	// ActiveTypes overrides the default active content-type vocabulary.
	ActiveTypes []string
}

// UploadServedOracle grades upload acceptance plus serve-back behaviour.
// Evidence ladder: reject / firm / confirmed (no new level).
type UploadServedOracle struct{}

func (UploadServedOracle) Name() string { return "upload-served" }

// defaultUploadActiveTypes lists content types a browser or server treats as
// active content (script or markup execution) rather than inert data.
var defaultUploadActiveTypes = []string{
	"text/html", "application/xhtml+xml", "image/svg+xml",
	"application/xml", "text/xml",
	"application/javascript", "text/javascript", "application/x-javascript",
}

// contentTypeBase strips parameters ("text/html; charset=utf-8" -> "text/html").
func contentTypeBase(h http.Header) string {
	if h == nil {
		return ""
	}
	ct := strings.ToLower(strings.TrimSpace(h.Get("Content-Type")))
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

// uploadActiveType reports whether a base content type executes.
func uploadActiveType(ct string, extra []string) bool {
	if ct == "" {
		return false
	}
	for _, t := range defaultUploadActiveTypes {
		if ct == t {
			return true
		}
	}
	for _, t := range extra {
		if ct == strings.ToLower(strings.TrimSpace(t)) {
			return true
		}
	}
	return false
}

// Verify enforces the upload plus serve-back workflow.
// What: Upload must be accepted, the artifact must come back with our canary,
// and the control URL must stay clean. The served content type then decides
// between confirmed (active content) and firm (inert or unknown).
// Why: An accepted upload alone proves nothing; only the way the artifact is
// served back distinguishes a hardening gap from executable stored content.
func (UploadServedOracle) Verify(ctx context.Context, cls baseline.Classification, tainted bool, p UploadServedParams) (*Evidence, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if g := guard(cls, tainted); g != nil {
		return g, nil
	}
	if strings.TrimSpace(p.Canary) == "" {
		return &Evidence{Verdict: VerdictReject, Note: "empty canary"}, nil
	}
	// Exchange 1: the upload must have been attempted and accepted.
	if p.UploadStatus == 0 && strings.TrimSpace(p.UploadBody) == "" {
		return &Evidence{Verdict: VerdictReject, Note: "upload exchange missing"}, nil
	}
	if p.UploadStatus >= 400 {
		return &Evidence{
			Verdict: VerdictReject,
			Artifacts: map[string]string{
				"workflow":      "upload+fetch",
				"upload_status": strconv.Itoa(p.UploadStatus),
			},
			Note: "upload rejected by the server",
		}, nil
	}
	// Exchange 2: the artifact must be retrievable.
	if p.FetchStatus == 0 || p.FetchStatus >= 400 {
		return &Evidence{
			Verdict: VerdictReject,
			Artifacts: map[string]string{
				"workflow":     "upload+fetch",
				"fetch_status": strconv.Itoa(p.FetchStatus),
			},
			Note: "uploaded artifact not served back",
		}, nil
	}
	if !strings.Contains(p.FetchBody, p.Canary) {
		return &Evidence{
			Verdict:   VerdictReject,
			Artifacts: map[string]string{"workflow": "upload+fetch"},
			Note:      "artifact served without our payload",
		}, nil
	}
	// A dirty control means the URL serves the payload regardless of the
	// upload, so nothing about the upload is proven.
	if p.ControlBody != "" || p.ControlStatus != 0 {
		if strings.Contains(p.ControlBody, p.Canary) {
			return &Evidence{
				Verdict:   VerdictReject,
				Artifacts: map[string]string{"workflow": "upload+fetch"},
				Note:      "control URL carries the payload too — attribution lost",
			}, nil
		}
	}
	ct := contentTypeBase(p.FetchHeaders)
	art := map[string]string{"workflow": "upload+fetch", "content_type": ct}
	if uploadActiveType(ct, p.ActiveTypes) {
		return &Evidence{
			Verdict:                VerdictAccept,
			ConfidenceContribution: plugin.ConfidenceConfirmed,
			Artifacts:              art,
			Note:                   "uploaded payload served as active content (" + ct + ")",
		}, nil
	}
	return &Evidence{
		Verdict:                VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceFirm,
		Artifacts:              art,
		Note:                   "upload accepted with a mismatched type; artifact served as inert content",
	}, nil
}
