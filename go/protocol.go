package main

// Job mirrors the Python bridge payload (core/goworker.py).
type Job struct {
	Job     string            `json:"job"`
	Target  string            `json:"target"`
	HTML    string            `json:"html"`
	Headers map[string]string `json:"headers"`
	Timeout int               `json:"timeout"`
	// Ranking inputs: data comes from Python, algorithm lives in rank.go.
	Techs []string `json:"techs"`
	Paths []string `json:"paths"`
	URLs  []string `json:"urls"`
	Limit int      `json:"limit"`
	// Fetch inputs: one round-trip fans out to N GETs (see fetch.go).
	Requests     []FetchReq `json:"requests"`
	Workers      int        `json:"workers"`
	SnippetBytes int        `json:"snippet_bytes"`
	MaxBody      int        `json:"max_body"`
}

// FetchReq is one request: URL + method/body + headers (UA, Cookie) baked
// by Python. GET with no body is the common case; POST form probes carry
// Form (url-encoded) or raw Body + ContentType.
type FetchReq struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type"`
	Form        map[string]string `json:"form"`
	Headers     map[string]string `json:"headers"`
}

// FetchRes is the verdict input Python judges. Length is bytes read, saturating
// at MaxBody+1 (dir-brute verdicts only need exact lengths for small pages;
// baselines are small 404s); Snippet is its head (SnippetBytes) with
// invalid UTF-8 replaced so stdout stays valid JSON.
type FetchRes struct {
	URL       string `json:"url"`
	FinalURL  string `json:"final_url"`
	Status    int    `json:"status"`
	Length    int    `json:"length"`
	Snippet   string `json:"snippet"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
}

// GoFinding is the wire subset of core.scanner.Finding.
type GoFinding struct {
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail"`
	URL        string `json:"url"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
}

// Result is the single stdout document.
type Result struct {
	OK       bool        `json:"ok"`
	Job      string      `json:"job"`
	Findings []GoFinding `json:"findings"`
	Techs    []string    `json:"techs,omitempty"`
	Paths    []string    `json:"paths,omitempty"`
	URLs     []string    `json:"urls,omitempty"`
	Fetches  []FetchRes  `json:"fetches,omitempty"`
	Pong     bool        `json:"pong,omitempty"`
	Error    string      `json:"error,omitempty"`
}
