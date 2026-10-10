package main

import "strings"

type marker struct {
	tech  string
	marks []string
}

// Mirrors TECH_MARKERS in core/deep/_shared.py (keep in sync).
var techMarkers = []marker{
	{"wordpress", []string{"wp-content", "wp-includes", "wp-json"}},
	{"nextjs", []string{"_next/static", "__next_data__"}},
	{"node", []string{"express", "x-powered-by: express"}},
	{"php", []string{"x-powered-by: php", "phpsessid", "wordpress"}},
	{"java", []string{"jsessionid", "x-powered-by: servlet", "spring", "actuator"}},
	{"python", []string{"csrftoken", "django", "wsgi", "flask"}},
}

func detectTechs(html string, headers map[string]string) []string {
	var sb strings.Builder
	if len(html) > 6000 {
		html = html[:6000]
	}
	sb.WriteString(html)
	sb.WriteString(" ")
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString(" ")
	}
	blob := strings.ToLower(sb.String())
	var techs []string
	for _, m := range techMarkers {
		for _, mark := range m.marks {
			if strings.Contains(blob, mark) {
				techs = append(techs, m.tech)
				break
			}
		}
	}
	if techs == nil {
		techs = []string{}
	}
	return techs
}

func handleTechFingerprint(job Job) Result {
	techs := detectTechs(job.HTML, job.Headers)
	findings := []GoFinding{}
	if len(techs) > 0 {
		target := job.Target
		if target == "" {
			target = "(unknown target)"
		}
		findings = append(findings, GoFinding{
			Title:      "Technology fingerprint (go-worker)",
			Severity:   "INFO",
			Detail:     "Stack detected by go-worker: " + strings.Join(techs, ", "),
			URL:        target,
			Evidence:   strings.Join(techs, ","),
			Confidence: "High",
		})
	}
	return Result{OK: true, Job: job.Job, Findings: findings, Techs: techs}
}
