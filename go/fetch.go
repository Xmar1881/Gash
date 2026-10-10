package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// fetchBatch fans N GETs out over a bounded worker pool, input order kept.
// Semantics are fetch-only: verdicts stay in Python
// (core/scan/enumeration._verdict_dir, classify_reflection callers), so FP
// rules cannot drift between the Go path and the Python fallback.
func fetchBatch(job Job) ([]FetchRes, string) {
	if len(job.Requests) == 0 {
		return []FetchRes{}, ""
	}
	if len(job.Requests) > 200 {
		return nil, "fetch-batch: too many requests (cap 200)"
	}
	workers := job.Workers
	if workers <= 0 {
		workers = 20
	}
	if workers > 32 {
		workers = 32
	}
	timeout := job.Timeout
	if timeout <= 0 {
		timeout = 8
	}
	snippetBytes := job.SnippetBytes
	if snippetBytes <= 0 {
		snippetBytes = 4096
	}
	maxBody := job.MaxBody
	if maxBody <= 0 {
		maxBody = 2 << 20 // 2 MiB: verdicts only read the head
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	out := make([]FetchRes, len(job.Requests))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, req := range job.Requests {
		wg.Add(1)
		go func(i int, req FetchReq) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = fetchOne(client, req, snippetBytes, maxBody)
		}(i, req)
	}
	wg.Wait()
	return out, ""
}

func fetchOne(client *http.Client, req FetchReq, snippetBytes, maxBody int) FetchRes {
	res := FetchRes{URL: req.URL}
	if req.URL == "" {
		res.Error = "empty url"
		return res
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	var bodyReader io.Reader
	contentType := req.ContentType
	if len(req.Form) > 0 {
		form := url.Values{}
		for k, v := range req.Form {
			form.Set(k, v)
		}
		bodyReader = strings.NewReader(form.Encode())
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
	} else if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequest(method, req.URL, bodyReader)
	if err != nil {
		res.Error = "bad request: " + err.Error()
		return res
	}
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := client.Do(httpReq)
	if err != nil && (method == "GET" || method == "HEAD") {
		// One retry for transient transport failures (burst dial races,
		// reset connections): safe methods only, bounded 100ms.
		// Python-side per-URL retry remains the backstop.
		time.Sleep(100 * time.Millisecond)
		resp, err = client.Do(httpReq)
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)+1))
	if err != nil {
		res.Error = "read: " + err.Error()
		return res
	}
	res.Status = resp.StatusCode
	if resp.Request != nil && resp.Request.URL != nil {
		res.FinalURL = resp.Request.URL.String()
	}
	res.Length = len(body)
	if len(body) > maxBody {
		res.Truncated = true
		body = body[:maxBody]
	}
	head := body
	if len(head) > snippetBytes {
		head = head[:snippetBytes]
	}
	res.Snippet = strings.ToValidUTF8(string(head), "\uFFFD")
	return res
}
