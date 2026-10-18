// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// Faz 2: SSH banner sürümü → bilinen danışmanlık eşlemesi (GASH-056).
//
// Sınır sözleşmesi: yalnızca banner'daki OpenSSH sürümü, dar ve elle
// küratörlü bir sunucu-tarafı tabloyla karşılaştırılır. Banner sunucunun
// kendi beyanıdır; yamalanmış/spoof edilmiş olabilir ve satıcı
// geri-uyarlamaları (backport) sürüm numarasına yansımayabilir → güven
// tavanı tentative'dir. Diğer SSH yazılımları (Dropbear, Cisco vb.) için
// eşleme YAPILMAZ; tablo dışı sürümler sessizdir.

// opensshVersion OpenSSH sürüm üçlüsüdür (banner'da "p" yoksa patch=0).
type opensshVersion struct {
	major, minor, patch int
}

// compare -1/0/1 döner (sürüm üçlüsü sözlük sırasıyla).
func (v opensshVersion) compare(o opensshVersion) int {
	switch {
	case v.major != o.major:
		if v.major < o.major {
			return -1
		}
		return 1
	case v.minor != o.minor:
		if v.minor < o.minor {
			return -1
		}
		return 1
	case v.patch != o.patch:
		if v.patch < o.patch {
			return -1
		}
		return 1
	}
	return 0
}

// readVersionNumber sürüm sayısını okur ve indeksi ilerletir (saf yardımcı).
// Saçma büyük sayılar sessizce reddedilir (düşmanca banner bellek/CPU yakmaz).
func readVersionNumber(s string, i *int) (int, bool) {
	start := *i
	n := 0
	for *i < len(s) && s[*i] >= '0' && s[*i] <= '9' {
		n = n*10 + int(s[*i]-'0')
		*i++
		if n > 1_000_000 {
			return 0, false
		}
	}
	if *i == start {
		return 0, false
	}
	return n, true
}

// parseOpenSSHVersion "OpenSSH_x.y[pN]" önekini çözer; satıcı soneki
// (örn. "9.2p1 Debian-2+deb12u2") yok sayılır.
// What: Yalnızca "OpenSSH_" öneki kabul edilir; major.minor zorunlu, pN
// isteğe bağlı (yoksa 0). "OpenSSH_x.y", "OpenSSH_9" gibi bozuk girdiler
// ok=false döner (sahte sürüm iddiası üretilmez).
// Why: Tolerant reader: bilinmeyen satıcı sonekleri eşlemeyi bozmamalı.
func parseOpenSSHVersion(software string) (opensshVersion, bool) {
	s := strings.TrimSpace(software)
	const prefix = "OpenSSH_"
	if !strings.HasPrefix(s, prefix) {
		return opensshVersion{}, false
	}
	rest := s[len(prefix):]
	i := 0
	major, ok := readVersionNumber(rest, &i)
	if !ok || i >= len(rest) || rest[i] != '.' {
		return opensshVersion{}, false
	}
	i++
	minor, ok := readVersionNumber(rest, &i)
	if !ok {
		return opensshVersion{}, false
	}
	v := opensshVersion{major: major, minor: minor}
	if i < len(rest) && rest[i] == 'p' {
		i++
		patch, pok := readVersionNumber(rest, &i)
		if !pok {
			return opensshVersion{}, false
		}
		v.patch = patch
	}
	return v, true
}

// sshAdvisory dar küratörlü sunucu-tarafı danışmanlık kaydıdır.
// What: min (dahil; sıfır → alt sınır yok) ve max sınırı sürüm üçlüsüyle
// karşılaştırılır; maxInclusive=false ise max'tan küçük olanlar eşleşir.
// maxMinorInclusive=true yalnızca major.minor düzeyinde kapsar (≤ 7.7 gibi
// patch'ten bağımsız üst sınırlar).
// Why: Sınır semantiği veriyle açıkça taşınır; istisnalar kod dallarına
// dağılmaz ve tablo testlerle kilitlenir.
type sshAdvisory struct {
	cve               string
	summary           string
	severity          plugin.Severity
	min               opensshVersion
	max               opensshVersion
	maxInclusive      bool
	maxMinorInclusive bool
}

// matches sürümün danışmanlık aralığında olup olmadığını döner (saf).
func (a sshAdvisory) matches(v opensshVersion) bool {
	if a.min != (opensshVersion{}) && v.compare(a.min) < 0 {
		return false
	}
	if a.max == (opensshVersion{}) {
		return true
	}
	if a.maxMinorInclusive {
		if v.major > a.max.major || (v.major == a.max.major && v.minor > a.max.minor) {
			return false
		}
		return true
	}
	c := v.compare(a.max)
	if a.maxInclusive {
		return c <= 0
	}
	return c < 0
}

// sshAdvisories küratörlü sunucu-tarafı OpenSSH danışmanlık tablosudur.
// What: Yalnızca yaygın belgelenmiş, sunucuyla ilgili girişler; bilinçli
// olarak dar tutulur (sürüm aralıkları yayın notlarıyla hizalanır).
// Why: Banner → CVE eşlemesi yanlış pozitife açıktır; geniş tablo yerine
// dar ve bakımı yapılabilir bir liste tercih edilir (GASH-026 disiplini).
var sshAdvisories = []sshAdvisory{
	{
		cve:          "CVE-2024-6387",
		summary:      "regreSSHion: glibc tabanlı sistemlerde kimlik doğrulamasız uzaktan kod yürütme (glibc koşulu)",
		severity:     plugin.SeverityHigh,
		min:          opensshVersion{major: 8, minor: 5, patch: 1},
		max:          opensshVersion{major: 9, minor: 7, patch: 1},
		maxInclusive: true,
	},
	{
		cve:      "CVE-2023-48795",
		summary:  "Terrapin: kanal öneki sıkıştırmasıyla araya giren saldırısı (MITM)",
		severity: plugin.SeverityMedium,
		max:      opensshVersion{major: 9, minor: 6, patch: 0},
	},
	{
		cve:      "CVE-2021-41617",
		summary:  "sshd yetki yükseltme (yapılandırmaya bağlı, ayrıcalıklı yardımcı program)",
		severity: plugin.SeverityMedium,
		max:      opensshVersion{major: 8, minor: 8, patch: 1},
	},
	{
		cve:               "CVE-2018-15473",
		summary:           "kimlik doğrulama öncesi kullanıcı adı numaralandırması",
		severity:          plugin.SeverityMedium,
		max:               opensshVersion{major: 7, minor: 7, patch: 0},
		maxMinorInclusive: true,
	},
	{
		cve:      "CVE-2016-10012",
		summary:  "sshd ayrıcalık ayrımı (privsep) bellek sınırı ihlali",
		severity: plugin.SeverityMedium,
		max:      opensshVersion{major: 7, minor: 4, patch: 0},
	},
	{
		cve:      "CVE-2015-6564",
		summary:  "privsep kullanımdan sonra serbest bırakma (use-after-free)",
		severity: plugin.SeverityMedium,
		max:      opensshVersion{major: 7, minor: 0, patch: 0},
	},
	{
		cve:      "CVE-2015-5600",
		summary:  "MaxAuthTries atlatma / kimlik doğrulama hizmet dışı bırakma",
		severity: plugin.SeverityMedium,
		max:      opensshVersion{major: 7, minor: 0, patch: 0},
	},
}

// sshVersionNote satıcı geri-uyarlaması uyarısıdır (kanıt ve bulgu notu).
const sshVersionNote = "banner tabanlı sürüm eşlemesi (heuristik); satıcı geri-uyarlamaları (backport) bu açıkları zaten yamamış olabilir"

// SSHVersionFindings OpenSSH banner sürümünü danışmanlık tablosuyla eşler (GASH-056).
// What: Eşleşen TÜM CVE'ler TEK bulguda toplanır (şiddet = en yüksek eşleşme);
// eşleşme yoksa, bozuk sürümde veya OpenSSH dışı yazılımda bulgu üretilmez.
// Kanıt: software, cves (virgüllü, tablo sırasıyla), signal=ssh-vulnerable-version,
// note (geri-uyarlama uyarısı).
// Why: Banner beyanı yamalanmış/spoof edilmiş olabilir ve sürüm numarası
// satıcı yamalarını göstermez → CVE eşlemesi kanıtlanmadı, tavan tentative'dir
// (sömürü denemesi yok; yalnızca beyan karşılaştırması).
func SSHVersionFindings(target, software string) []Finding {
	v, ok := parseOpenSSHVersion(software)
	if !ok {
		return nil
	}
	var matched []sshAdvisory
	best := plugin.Severity("")
	for _, a := range sshAdvisories {
		if !a.matches(v) {
			continue
		}
		matched = append(matched, a)
		if best == "" || sshSeverityRank(a.severity) > sshSeverityRank(best) {
			best = a.severity
		}
	}
	if len(matched) == 0 {
		return nil
	}
	cves := make([]string, 0, len(matched))
	for _, a := range matched {
		cves = append(cves, a.cve)
	}
	cveList := strings.Join(cves, ",")
	return []Finding{{
		RuleID: "GASH-056", CWE: "CWE-1395",
		Title: fmt.Sprintf("SSH sürümü bilinen danışmanlıklarla eşleşiyor (%d CVE)", len(matched)),
		Desc: "Banner OpenSSH " + fmt.Sprintf("%d.%dp%d", v.major, v.minor, v.patch) +
			" bildiriyor; küratörlü tablo " + cveList + " ile eşleşti. " +
			"Sürüm eşlemesi heuristiktir: satıcı geri-uyarlamaları yamamış olabilir, sömürü doğrulanmadı.",
		Severity: best, Confidence: plugin.ConfidenceTentative,
		Target: target, PluginID: "proto-ssh-banner", OracleName: "ssh",
		Evidence: map[string]string{
			"software":         sanitizeProtoBanner(strings.TrimSpace(software), 128),
			"software_version": fmt.Sprintf("%d.%dp%d", v.major, v.minor, v.patch),
			"cves":             cveList,
			"cve_count":        strconv.Itoa(len(matched)),
			"signal":           "ssh-vulnerable-version",
			"note":             sshVersionNote,
		},
		Note: "salt-okuma banner gözlemi; sürüm eşlemesi kanıtlanmadı, sömürü denemesi yok, tavan tentative",
		Tags: []string{"ssh", "version-disclosure", "advisory"},
	}}
}
