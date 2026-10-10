package main

import "testing"

func TestRunDispatch(t *testing.T) {
	if r := run(Job{Job: "ping"}); !r.OK || !r.Pong {
		t.Fatalf("ping failed: %+v", r)
	}
	if r := run(Job{Job: "nope"}); r.OK {
		t.Fatalf("unknown job must fail: %+v", r)
	}
	r := run(Job{Job: "rank-wordlist", Techs: []string{"php"},
		Paths: []string{"a", "x.php"}, Limit: 10})
	if len(r.Paths) != 2 || r.Paths[0] != "x.php" {
		t.Fatalf("rank-wordlist dispatch wrong: %+v", r)
	}
	r = run(Job{Job: "prioritize-urls",
		URLs: []string{"http://h/a", "http://h/?x=1"}, Limit: 10})
	if len(r.URLs) != 2 || r.URLs[0] != "http://h/?x=1" {
		t.Fatalf("prioritize-urls dispatch wrong: %+v", r)
	}
	if r := run(Job{Job: "fetch-batch"}); !r.OK || r.Fetches == nil {
		t.Fatalf("empty fetch-batch must succeed: %+v", r)
	}
}
