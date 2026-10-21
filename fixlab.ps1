$f='internal\bench\lab.go'
$s=[System.IO.File]::ReadAllText($f)

$repl = @{
'	case r.URL.Path == "/xss/reflect" || r.URL.Path == "/xss/attr" || r.URL.Path == "/xss/attr-quoted" ||
		r.URL.Path == "/xss/attr-single" || r.URL.Path == "/xss/js" || r.URL.Path == "/xss/js-double" ||
		r.URL.Path == "/xss/url" || r.URL.Path == "/xss/json-raw" || r.URL.Path == "/xss/textarea" ||
		r.URL.Path == "/xss/title" || r.URL.Path == "/xss/escape" || r.URL.Path == "/xss/dom":
		l.xss(w, r)
' = '	case r.URL.Path == "/xss/reflect" || r.URL.Path == "/xss/reflect2" ||
		r.URL.Path == "/xss/attr" || r.URL.Path == "/xss/attr2" ||
		r.URL.Path == "/xss/attr-quoted" || r.URL.Path == "/xss/attr-quoted2" ||
		r.URL.Path == "/xss/attr-single" || r.URL.Path == "/xss/attr-single2" ||
		r.URL.Path == "/xss/js" || r.URL.Path == "/xss/js2" ||
		r.URL.Path == "/xss/js-double" || r.URL.Path == "/xss/js-double2" ||
		r.URL.Path == "/xss/url" || r.URL.Path == "/xss/url2" ||
		r.URL.Path == "/xss/json-raw" || r.URL.Path == "/xss/json-raw2" ||
		r.URL.Path == "/xss/escape" || r.URL.Path == "/xss/escape2" ||
		r.URL.Path == "/xss/textarea" || r.URL.Path == "/xss/title" || r.URL.Path == "/xss/dom":
		l.xss(w, r)
'
'	case r.URL.Path == "/sqli/clean":
		l.sqliClean(w, r)
' = '	case r.URL.Path == "/sqli/clean" || r.URL.Path == "/sqli/clean2":
		l.sqliClean(w, r)
'
'	case r.URL.Path == "/redirect/clean":
		l.redirectClean(w, r)
' = '	case r.URL.Path == "/redirect/clean" || r.URL.Path == "/redirect/clean2":
		l.redirectClean(w, r)
'
'	case r.URL.Path == "/clean/search":
		l.cleanSearch(w, r)
' = '	case r.URL.Path == "/robots.txt":
		l.artifact(w, "User-agent: *\nDisallow: /admin\nDisallow: /backup\n")
	case r.URL.Path == "/clean/search" || r.URL.Path == "/clean/search2":
		l.cleanSearch(w, r)
'
'	case r.URL.Path == "/denied":
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(FixtureDenied))
' = '	case r.URL.Path == "/denied" || r.URL.Path == "/denied2":
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(FixtureDenied))
'
'	case r.URL.Path == "/waf":
		l.waf(w, r)
' = '	case r.URL.Path == "/waf" || r.URL.Path == "/waf2":
		l.waf(w, r)
'
'	case r.URL.Path == "/slow":
		time.Sleep(1500 * time.Millisecond)
		l.page(w, "slow page done")
' = '	case r.URL.Path == "/slow" || r.URL.Path == "/slow2":
		time.Sleep(1500 * time.Millisecond)
		l.page(w, "slow page done")
'
}

foreach ($k in $repl.Keys) {
  if (-not $s.Contains($k)) { throw "pattern not found: $k" }
  $s = $s.Replace($k, $repl[$k])
}

# normalize xss path inside xss() so variants reuse same behavior
$oldXss = 'func (l *FixtureLab) xss(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, xssParamNames...)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch r.URL.Path {'
$newXss = 'func (l *FixtureLab) xss(w http.ResponseWriter, r *http.Request) {
	v := firstParam(r, xssParamNames...)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	path := strings.TrimSuffix(r.URL.Path, "2")
	switch path {'
if (-not $s.Contains($oldXss)) { throw "xss func not found" }
$s = $s.Replace($oldXss, $newXss)

[System.IO.File]::WriteAllText($f, $s)
Write-Host "updated lab.go"
