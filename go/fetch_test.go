package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchBatchStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("hello " + r.Header.Get("X-Probe")))
		case "/moved":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/secret":
			w.WriteHeader(403)
			_, _ = w.Write([]byte("blocked"))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte("nope"))
		}
	}))
	defer srv.Close()

	job := Job{Job: "fetch-batch", Timeout: 5, Workers: 4, Requests: []FetchReq{
		{URL: srv.URL + "/ok", Headers: map[string]string{"X-Probe": "p1"}},
		{URL: srv.URL + "/moved"},
		{URL: srv.URL + "/secret"},
		{URL: srv.URL + "/missing"},
	}}
	res, errStr := fetchBatch(job)
	if errStr != "" {
		t.Fatal(errStr)
	}
	if len(res) != 4 {
		t.Fatalf("want 4 results, got %d", len(res))
	}
	// input order kept
	if res[0].URL != srv.URL+"/ok" || res[3].URL != srv.URL+"/missing" {
		t.Fatalf("order not preserved: %+v", res)
	}
	if res[0].Status != 200 || !strings.Contains(res[0].Snippet, "hello p1") {
		t.Fatalf("ok wrong: %+v", res[0])
	}
	if res[1].Status != 200 || res[1].FinalURL != srv.URL+"/ok" {
		t.Fatalf("redirect not followed: %+v", res[1])
	}
	if res[2].Status != 403 {
		t.Fatalf("secret wrong: %+v", res[2])
	}
	if res[3].Status != 404 {
		t.Fatalf("missing wrong: %+v", res[3])
	}
	for _, fr := range res {
		if fr.Error != "" {
			t.Fatalf("unexpected error: %+v", fr)
		}
		if fr.Length <= 0 || fr.Snippet == "" {
			t.Fatalf("length/snippet missing: %+v", fr)
		}
	}
}

func TestFetchBatchLimits(t *testing.T) {
	big := strings.Repeat("A", 9000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	res, errStr := fetchBatch(Job{Job: "fetch-batch", Timeout: 5,
		SnippetBytes: 100, MaxBody: 1000,
		Requests: []FetchReq{{URL: srv.URL}}})
	if errStr != "" {
		t.Fatal(errStr)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if res[0].Length != 1001 {
		t.Fatalf("length must saturate at MaxBody+1: %+v", res[0])
	}
	if !res[0].Truncated || len(res[0].Snippet) != 100 {
		t.Fatalf("snippet must be the capped head: %+v", res[0])
	}
	// error host degrades per-URL, never fails the batch
	res, errStr = fetchBatch(Job{Job: "fetch-batch", Timeout: 2,
		Requests: []FetchReq{{URL: "http://127.0.0.1:1/"}, {URL: ""}}})
	if errStr != "" {
		t.Fatal(errStr)
	}
	if res[0].Error == "" || res[1].Error == "" {
		t.Fatalf("bad URLs must degrade per-URL: %+v", res)
	}
	// batch cap guards the worker
	many := make([]FetchReq, 201)
	for i := range many {
		many[i] = FetchReq{URL: "http://127.0.0.1/"}
	}
	if _, errStr := fetchBatch(Job{Job: "fetch-batch", Requests: many}); errStr == "" {
		t.Fatal("201 requests must be refused")
	}
	if _, errStr := fetchBatch(Job{Job: "fetch-batch"}); errStr != "" {
		t.Fatalf("empty batch must succeed: %s", errStr)
	}
}

func TestFetchBatchPost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Got-Method", r.Method)
		w.Header().Set("X-Got-CT", r.Header.Get("Content-Type"))
		w.WriteHeader(200)
		_, _ = w.Write([]byte("echo:" + string(raw)))
	}))
	defer srv.Close()

	res, errStr := fetchBatch(Job{Job: "fetch-batch", Timeout: 5, Requests: []FetchReq{
		{URL: srv.URL, Method: "POST", Form: map[string]string{"q": "gx1><svg"}},
		{URL: srv.URL, Method: "POST", Body: `{"q":"1"}`, ContentType: "application/json"},
		{URL: srv.URL},
	}})
	if errStr != "" {
		t.Fatal(errStr)
	}
	if len(res) != 3 {
		t.Fatalf("want 3 results, got %d", len(res))
	}
	if res[0].Status != 200 || !strings.Contains(res[0].Snippet, "echo:q=gx1") {
		t.Fatalf("form POST wrong: %+v", res[0])
	}
	if res[1].Status != 200 || !strings.Contains(res[1].Snippet, `echo:{"q":"1"}`) {
		t.Fatalf("raw POST wrong: %+v", res[1])
	}
	if res[2].Status != 200 || !strings.Contains(res[2].Snippet, "echo:") {
		t.Fatalf("plain GET wrong: %+v", res[2])
	}
}
