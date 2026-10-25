<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: plugins/README.md
What: Index of official reference plugins with category summary.
Why: Shows tier layout, testing, metric gate, and contribution entry points.
-->

# Reference Plugins

## Purpose

Official built-in plugins covering Tier 1 (YAML), Tier 2 (JS), and Tier 3 (native).
Each plugin ships positive + negative + ambiguous fixtures and a precision report.
The engine discovers this tree automatically; no `--load-plugin` flag exists.

## Quick Stats

| Tier | Count | Auto-discovered | Trust Required |
|------|------:|:---------------:|:--------------:|
| Tier 1 (YAML) | 174 | ✅ | ❌ |
| Tier 2 (JS) | 7 | ✅ | ❌ |
| Tier 2 (Native JS) | 1 | ✅ | ❌ |
| Tier 3 (Native) | 1 | ❌ | ✅ `gash plugins trust` |
| **Total** | **183** | | |

---

## Category Summary

| Category | Plugins | Tier | Key Oracle | Good First PR? |
|----------|---------|------|------------|----------------|
| **Cross-site Scripting** | 6 | 1/2 | `reflection`, `stored`, `execution` | ✅ `xss-attribute-injection` |
| **SQL Injection** | 6 | 1/2 | `error`, `differential`, `timing`, `oob` | ✅ `sqli-auth-bypass` |
| **Command Injection** | 3 | 1 | `error`, `timing`, `oob` | ✅ `command-injection-timing` |
| **Path Traversal / File** | 8 | 1 | `error` | ✅ `backup-file-exposure` |
| **SSRF / Open Redirect** | 6 | 1 | `redirect`, `oob`, `reflection` | ✅ `open-redirect-param` |
| **NoSQL / LDAP / SSTI** | 8 | 1 | `timing`, `differential`, `oob` | — |
| **GraphQL** | 5 | 1 | `version`, `differential` | — |
| **Auth / IDOR / Logic** | 10 | 1 | `differential`, `error` | ✅ `idor-differential` |
| **Misconfig / Headers** | 27 | 1 | `header`, `cookie`, `cors`, `header` modes | ✅ `cookie-flags` |
| **Deserialization / XXE** | 5 | 1 | `error` (deserialization, takeover, xpath, backup) | — |
| **Framework-specific** | 2 | 1 | `middleware-bypass`, `oob` | — |
| **Injection (JNDI, EL, SSI, JSONP, PP)** | 5 | 1 | `oob`, `reflection`, `error`, `differential` | — |
| **Info Disclosure** | 8 | 1 | `error`, `header`, `version` | ✅ `phpinfo-exposure` |
| **Cache / Takeover / Rate Limit** | 4 | 1 | `differential`, `error`, `header` | — |
| **Modern Headers / API Exposure** | 20 | 1 | `header`, `version`, `error` | ✅ `permissions-policy-missing` |
| **Critical Control-Plane / Secret Exposure** | 80 | 1 | `error` (`critical_exposure`) | ✅ `aws-credentials-exposure` |
| **Native PoC** | 1 | 3 | `header` | — |

---

## Plugin Index

### Cross-site Scripting (XSS)

| Plugin | Tier | Oracle | File | Good First PR |
|--------|------|--------|------|---------------|
| `xss-reflected-basic` | Tier 2 | `reflection` | `xss/xss-reflected-basic.js` | |
| `xss-attribute-injection` | Tier 1 | `reflection` | `xss/xss-attribute-injection.yaml` | ⭐ **Yes** |
| `xss-stored-basic` | Tier 1 | `reflection` | `xss/xss-stored-basic.yaml` | |
| `xss-stored-two-step` | Tier 2 | `stored` | `xss/xss-stored-two-step.js` | |
| `dom-sink-basic` | Tier 2 | `execution` (firm max) | `xss/dom-sink-basic.js` | |
| `xpath-injection-error` | Tier 1 | `error` (xpath) | `xpath/xpath-injection-error.yaml` | |

### SQL Injection

| Plugin | Tier | Oracle | File | Good First PR |
|--------|------|--------|------|---------------|
| `sqli-error-based` | Tier 2 | `error` | `sqli/sqli-error-based.js` | |
| `sqli-boolean-differential` | Tier 2 | `differential` | `sqli/sqli-boolean-differential.js` | |
| `sqli-time-based` | Tier 1 | `timing` | `sqli-time-based/sqli-time-based.yaml` | |
| `sqli-stacked-time` | Tier 1 | `timing` | `sqli/sqli-stacked-time.yaml` | |
| `sqli-auth-bypass` | Tier 1 | `error` | `sqli/sqli-auth-bypass.yaml` | ⭐ **Yes** |
| `blind-sqli-oob` | Tier 1 | `oob` (required) | `blind-sqli-oob/blind-sqli-oob.yaml` | |

### Command Injection

| Plugin | Tier | Oracle | File | Good First PR |
|--------|------|--------|------|---------------|
| `command-injection-error` | Tier 1 | `error` | `command-injection/command-injection-error.yaml` | |
| `command-injection-timing` | Tier 1 | `timing` | `command-injection/command-injection-timing.yaml` | ⭐ **Yes** |
| `command-injection-oob` | Tier 1 | `oob` (required) | `command-injection/command-injection-oob.yaml` | |

### Path Traversal & File Access

| Plugin | Tier | Oracle | File | Good First PR |
|--------|------|--------|------|---------------|
| `path-traversal-error` | Tier 1 | `error` | `path-traversal/path-traversal-error.yaml` | |
| `file-upload-unrestricted` | Tier 1 | `error` | `file-upload/file-upload-unrestricted.yaml` | |
| `backup-file-exposure` | Tier 1 | `error` (backup_file) | `backup-file/backup-file-exposure.yaml` | ⭐ **Yes** |
| `directory-listing` | Tier 1 | `error` (directory_listing) | `directory-listing/directory-listing.yaml` | |
| `source-map-exposure` | Tier 1 | `error` (source_map) | `source-map-exposure/source-map-exposure.yaml` | |
| `file-inclusion-rfi` | Tier 1 | `reflection` | `rfi/rfi-remote-include.yaml` | |
| `sensitive-file-exposure` | Tier 1 | `error` (backup_file) | `sensitive-file-exposure/sensitive-file-exposure.yaml` | |
| `rfi-remote-include` | Tier 1 | `reflection` | `rfi/rfi-remote-include.yaml` | |

### SSRF & Open Redirect

| Plugin | Tier | Oracle | File | Good First PR |
|--------|------|--------|------|---------------|
| `open-redirect-param` | Tier 1 | `redirect` | `redirect/open-redirect-param.yaml` | ⭐ **Yes** |
| `oauth-open-redirect` | Tier 1 | `redirect` | `oauth-open-redirect/oauth-open-redirect.yaml` | |
| `ssrf-blind-oob` | Tier 2 | `oob` (required) | `ssrf/ssrf-blind-oob.js` | |
| `ssrf-cloud-metadata` | Tier 1 | `reflection` | `ssrf/ssrf-cloud-metadata.yaml` | |
| `ssrf-internal-port-scan` | Tier 1 | `reflection` | `ssrf-internal/ssrf-internal-port-scan.yaml` | |
| `nextjs-image-optimizer-ssrf` | Tier 1 | `oob` (required) | `nextjs-image-optimizer-ssrf/nextjs-image-optimizer-ssrf.yaml` | |

### NoSQL / LDAP / SSTI

| Plugin | Tier | Oracle | File |
|--------|------|--------|------|
| `nosql-injection-error` | Tier 1 | `error` | `nosql/nosql-injection-error.yaml` |
| `nosql-auth-bypass-differential` | Tier 1 | `differential` | `nosql/nosql-auth-bypass-differential.yaml` |
| `nosql-injection-timing` | Tier 1 | `timing` | `nosql/nosql-injection-timing.yaml` |
| `ldap-injection-differential` | Tier 1 | `differential` | `ldap-injection/ldap-injection-differential.yaml` |
| `ldap-injection-oob` | Tier 1 | `oob` (required) | `ldap-blind/ldap-injection-oob.yaml` |
| `ldap-injection-blind` | Tier 1 | `differential` | `ldap-blind/ldap-injection-blind.yaml` |
| `ssti-blind-oob` | Tier 1 | `oob` (required) | `ssti/ssti-blind-oob.yaml` |
| `template-injection-reflection` | Tier 1 | `reflection` | `template-injection/template-injection-reflection.yaml` |
| `ssti-blind-timing` | Tier 1 | `timing` | `ssti/ssti-blind-timing.yaml` |

### GraphQL

| Plugin | Tier | Oracle | File |
|--------|------|--------|------|
| `graphql-endpoint-discovery` | Tier 1 | `version` | `graphql-discovery/graphql-endpoint-discovery.yaml` |
| `graphql-introspection-enabled` | Tier 1 | `version` (graphql_introspection) | `graphql-introspection/graphql-introspection-enabled.yaml` |
| `graphql-auth-bypass` | Tier 1 | `differential` (firm, requires auth) | `graphql-auth-bypass/graphql-auth-bypass.yaml` |
| `graphql-dos` | Tier 1 | `differential` (firm) | `graphql-dos/graphql-dos.yaml` |
| `jsonp-callback-injection` | Tier 1 | `reflection` | `jsonp-callback-injection/jsonp-callback-injection.yaml` |

### Auth / IDOR / Logic

| Plugin | Tier | Oracle | File | Good First PR |
|--------|------|--------|------|---------------|
| `idor-differential` | Tier 1 | `differential` | `idor/idor-differential.yaml` | ⭐ **Yes** |
| `mass-assignment-basic` | Tier 1 | `differential` (firm) | `mass-assignment/mass-assignment-basic.yaml` | |
| `hpp-parameter-pollution` | Tier 1 | `differential` | `hpp/hpp-parameter-pollution.yaml` | |
| `hpp-duplicate-emission` | Tier 2 | `differential` | `hpp/hpp-duplicate-emission.js` | |
| `verb-tampering-bypass` | Tier 1 | `verb-tamper` | `verb-tampering/verb-tampering-bypass.yaml` | |
| `ldap-injection-differential` | Tier 1 | `differential` | `ldap-injection/ldap-injection-differential.yaml` | |
| `nosql-auth-bypass-differential` | Tier 1 | `differential` (firm) | `nosql/nosql-auth-bypass-differential.yaml` | |
| `graphql-auth-bypass` | Tier 1 | `differential` (firm, requires auth) | `graphql-auth-bypass/graphql-auth-bypass.yaml` | |
| `clickjacking-frameable` | Tier 1 | `header` (frame) | `clickjacking/clickjacking-frameable.yaml` | |

### Misconfig & Headers

| Plugin | Tier | Oracle | File | Good First PR |
|--------|------|--------|------|---------------|
| `missing-security-headers` | Tier 1 | `header` (security) | `headers/missing-security-headers.yaml` | ⭐ **Yes** |
| `cookie-flags` | Tier 1 | `cookie` | `cookies/cookie-flags.yaml` | ⭐ **Yes** |
| `cors-misconfig` | Tier 1 | `cors` | `cors/cors-misconfig.yaml` | |
| `insecure-cors-preflight` | Tier 1 | `cors` | `insecure-cors/insecure-cors-preflight.yaml` | |
| `crlf-header-injection` | Tier 1 | `header` (crlf) | `crlf/crlf-header-injection.yaml` | |
| `http-response-splitting` | Tier 1 | `header` | `http-response-splitting/http-response-splitting.yaml` | |
| `csrf-token-absence` | Tier 1 | `header` (csrf) | `csrf/csrf-token-absence.yaml` | |
| `clickjacking-frameable` | Tier 1 | `header` (frame) | `clickjacking/clickjacking-frameable.yaml` | |
| `jwt-token-exposure` | Tier 1 | `header` (jwt) | `jwt-exposure/jwt-token-exposure.yaml` | |
| `jwt-alg-confusion` | Tier 1 | `header` (jwt_alg) | `jwt-alg-confusion/jwt-alg-confusion.yaml` | |
| `jwt-none-alg-confusion` | Tier 1 | `header` | `jwt-none/jwt-none-alg-confusion.yaml` | |
| `host-header-injection` | Tier 1 | `header` (host_header) | `host-header/host-header-injection.yaml` | |
| `http-method-override-abuse` | Tier 1 | `header` | `http-method-override/http-method-override-abuse.yaml` | |
| `error-message-disclosure` | Tier 1 | `error` (generic_error) | `error-disclosure/error-message-disclosure.yaml` | |
| `debug-endpoint-exposure` | Tier 1 | `error` (generic_error + management_endpoint) | `debug-endpoint-exposure/debug-endpoint-exposure.yaml` | |
| `management-endpoint-exposure` | Tier 1 | `error` (management_endpoint) | `management-endpoint-exposure/management-endpoint-exposure.yaml` | |
| `phpinfo-exposure` | Tier 1 | `error` (phpinfo) | `phpinfo-exposure/phpinfo-exposure.yaml` | ⭐ **Yes** |
| `webdav-enabled` | Tier 1 | `header` (webdav) | `webdav-enabled/webdav-enabled.yaml` | |
| `cve-dependency-scan` | Tier 1 | `version` | `cve/cve-dependency-scan.yaml` | |
| `server-version-disclosure` | Tier 1 | `version` | `version-disclosure/server-version-disclosure.yaml` | |
| `missing-rate-limit` | Tier 1 | `header` (ratelimit) | `rate-limit/missing-rate-limit.yaml` | |
| `subdomain-takeover-basic` | Tier 1 | `error` (takeover) | `takeover/subdomain-takeover-basic.yaml` | |
| `cache-poisoning-host-header` | Tier 1 | `differential` | `cache-poisoning/cache-poisoning-host-header.yaml` | |
| `web-cache-poisoning-basic` | Tier 1 | `differential` | `web-cache/web-cache-poisoning-basic.yaml` | |

### Deserialization / XXE / SSI

| Plugin | Tier | Oracle | File |
|--------|------|--------|------|
| `insecure-deserialization-error` | Tier 1 | `error` (deserialization) | `deserialization/insecure-deserialization-error.yaml` |
| `xxe-oob` | Tier 1 | `oob` (required) | `xxe/xxe-oob.yaml` |
| `xxe-reflected-basic` | Tier 1 | `reflection` | `xxe/xxe-reflected-basic.yaml` |
| `xxe-blind-oob` | Tier 1 | `oob` (required) | `xxe-blind/xxe-blind-oob.yaml` |
| `xml-external-entity-blind` | Tier 1 | `error` | `xxe-blind-oob/xml-external-entity-blind.yaml` |
| `ssi-injection` | Tier 1 | `error` (ssi) | `ssi-injection/ssi-injection.yaml` |

### Framework-specific

| Plugin | Tier | Oracle | File |
|--------|------|--------|------|
| `nextjs-middleware-bypass` | Tier 1 | `middleware-bypass` | `nextjs-middleware-bypass/nextjs-middleware-bypass.yaml` |
| `nextjs-image-optimizer-ssrf` | Tier 1 | `oob` (required) | `nextjs-image-optimizer-ssrf/nextjs-image-optimizer-ssrf.yaml` |

### Injection Variants

| Plugin | Tier | Oracle | File |
|--------|------|--------|------|
| `log4shell-jndi` | Tier 1 | `oob` (required) | `log4shell-jndi/log4shell-jndi.yaml` |
| `expression-language-injection` | Tier 1 | `reflection` | `expression-language-injection/expression-language-injection.yaml` |
| `jsonp-callback-injection` | Tier 1 | `reflection` | `jsonp-callback-injection/jsonp-callback-injection.yaml` |
| `prototype-pollution-differential` | Tier 1 | `differential` | `prototype-pollution/prototype-pollution-differential.yaml` |
| `ssi-injection` | Tier 1 | `error` (ssi) | `ssi-injection/ssi-injection.yaml` |

### Info Disclosure

| Plugin | Tier | Oracle | File | Good First PR |
|--------|------|--------|------|---------------|
| `backup-file-exposure` | Tier 1 | `error` (backup_file) | `backup-file/backup-file-exposure.yaml` | ⭐ **Yes** |
| `directory-listing` | Tier 1 | `error` (directory_listing) | `directory-listing/directory-listing.yaml` | |
| `source-map-exposure` | Tier 1 | `error` (source_map) | `source-map-exposure/source-map-exposure.yaml` | |
| `sensitive-file-exposure` | Tier 1 | `error` (backup_file) | `sensitive-file-exposure/sensitive-file-exposure.yaml` | |
| `phpinfo-exposure` | Tier 1 | `error` (phpinfo) | `phpinfo-exposure/phpinfo-exposure.yaml` | ⭐ **Yes** |
| `management-endpoint-exposure` | Tier 1 | `error` (management_endpoint) | `management-endpoint-exposure/management-endpoint-exposure.yaml` | |
| `server-version-disclosure` | Tier 1 | `version` | `version-disclosure/server-version-disclosure.yaml` | |
| `cve-dependency-scan` | Tier 1 | `version` | `cve/cve-dependency-scan.yaml` | |

### Cache / Takeover / Rate Limit

| Plugin | Tier | Oracle | File |
|--------|------|--------|------|
| `subdomain-takeover-basic` | Tier 1 | `error` (takeover) | `takeover/subdomain-takeover-basic.yaml` |
| `web-cache-poisoning-basic` | Tier 1 | `differential` | `web-cache/web-cache-poisoning-basic.yaml` |
| `cache-poisoning-host-header` | Tier 1 | `differential` | `cache-poisoning/cache-poisoning-host-header.yaml` |
| `missing-rate-limit` | Tier 1 | `header` (ratelimit) | `rate-limit/missing-rate-limit.yaml` |

### Critical Control-Plane / Secret Exposure

These read-only probes cover rare but high-impact exposure surfaces. Their
custom `critical_exposure` signatures are marker-based and capped at `firm`;
they do not claim browser execution, authentication bypass, or RCE by
themselves.

| Plugin | Tier | Oracle | File | Severity |
|--------|------|--------|------|----------|
| `aws-credentials-exposure` | Tier 1 | `error` (`critical_exposure`) | `aws-credentials/aws-credentials-exposure.yaml` | critical |
| `npmrc-token-exposure` | Tier 1 | `error` (`critical_exposure`) | `npmrc-token/npmrc-token-exposure.yaml` | critical |
| `composer-auth-exposure` | Tier 1 | `error` (`critical_exposure`) | `composer-auth/composer-auth-exposure.yaml` | critical |
| `terraform-state-exposure` | Tier 1 | `error` (`critical_exposure`) | `terraform-state/terraform-state-exposure.yaml` | critical |
| `kubernetes-config-exposure` | Tier 1 | `error` (`critical_exposure`) | `kubernetes-config/kubernetes-config-exposure.yaml` | critical |
| `gitlab-runner-config-exposure` | Tier 1 | `error` (`critical_exposure`) | `gitlab-runner/gitlab-runner-config-exposure.yaml` | critical |
| `spring-config-exposure` | Tier 1 | `error` (`critical_exposure`) | `spring-config/spring-config-exposure.yaml` | high |
| `vault-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `vault-api/vault-api-exposure.yaml` | critical |
| `consul-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `consul-api/consul-api-exposure.yaml` | high |
| `etcd-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `etcd-api/etcd-api-exposure.yaml` | critical |
| `docker-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `docker-api/docker-api-exposure.yaml` | critical |
| `kubernetes-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `kubernetes-api/kubernetes-api-exposure.yaml` | critical |
| `jenkins-script-console-exposure` | Tier 1 | `error` (`critical_exposure`) | `jenkins-script/jenkins-script-console-exposure.yaml` | critical |
| `jmx-console-exposure` | Tier 1 | `error` (`critical_exposure`) | `jmx-console/jmx-console-exposure.yaml` | critical |
| `solr-admin-exposure` | Tier 1 | `error` (`critical_exposure`) | `solr-admin/solr-admin-exposure.yaml` | high |
| `elasticsearch-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `elasticsearch-api/elasticsearch-api-exposure.yaml` | critical |
| `kibana-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `kibana-api/kibana-api-exposure.yaml` | high |
| `grafana-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `grafana-api/grafana-api-exposure.yaml` | high |
| `rabbitmq-management-exposure` | Tier 1 | `error` (`critical_exposure`) | `rabbitmq-management/rabbitmq-management-exposure.yaml` | critical |
| `jupyter-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `jupyter-api/jupyter-api-exposure.yaml` | critical |
| `phpmyadmin-exposure` | Tier 1 | `error` (`critical_exposure`) | `phpmyadmin/phpmyadmin-exposure.yaml` | critical |
| `adminer-exposure` | Tier 1 | `error` (`critical_exposure`) | `adminer/adminer-exposure.yaml` | critical |
| `laravel-debug-exposure` | Tier 1 | `error` (`critical_exposure`) | `laravel-debug/laravel-debug-exposure.yaml` | high |
| `django-debug-exposure` | Tier 1 | `error` (`critical_exposure`) | `django-debug/django-debug-exposure.yaml` | high |
| `h2-console-exposure` | Tier 1 | `error` (`critical_exposure`) | `h2-console/h2-console-exposure.yaml` | critical |
| `saml-metadata-exposure` | Tier 1 | `error` (`critical_exposure`) | `saml-metadata/saml-metadata-exposure.yaml` | high |
| `oauth-client-secret-exposure` | Tier 1 | `error` (`critical_exposure`) | `oauth-client-secret/oauth-client-secret-exposure.yaml` | critical |
| `github-actions-config-exposure` | Tier 1 | `error` (`critical_exposure`) | `github-actions/github-actions-config-exposure.yaml` | high |
| `heapdump-exposure` | Tier 1 | `error` (`critical_exposure`) | `heapdump/heapdump-exposure.yaml` | critical |
| `minio-admin-exposure` | Tier 1 | `error` (`critical_exposure`) | `minio-admin/minio-admin-exposure.yaml` | critical |
| `azure-credentials-exposure` | Tier 1 | `error` (`critical_exposure`) | `azure-credentials/azure-credentials-exposure.yaml` | critical |
| `gcp-service-account-exposure` | Tier 1 | `error` (`critical_exposure`) | `gcp-service-account/gcp-service-account-exposure.yaml` | critical |
| `digitalocean-token-exposure` | Tier 1 | `error` (`critical_exposure`) | `digitalocean-token/digitalocean-token-exposure.yaml` | critical |
| `slack-token-exposure` | Tier 1 | `error` (`critical_exposure`) | `slack-token/slack-token-exposure.yaml` | critical |
| `stripe-secret-exposure` | Tier 1 | `error` (`critical_exposure`) | `stripe-secret/stripe-secret-exposure.yaml` | critical |
| `twilio-token-exposure` | Tier 1 | `error` (`critical_exposure`) | `twilio-token/twilio-token-exposure.yaml` | critical |
| `sendgrid-key-exposure` | Tier 1 | `error` (`critical_exposure`) | `sendgrid-key/sendgrid-key-exposure.yaml` | critical |
| `private-key-exposure` | Tier 1 | `error` (`critical_exposure`) | `private-key/private-key-exposure.yaml` | critical |
| `ssh-private-key-exposure` | Tier 1 | `error` (`critical_exposure`) | `ssh-private-key/ssh-private-key-exposure.yaml` | critical |
| `jwt-secret-exposure` | Tier 1 | `error` (`critical_exposure`) | `jwt-secret/jwt-secret-exposure.yaml` | critical |
| `ansible-vault-exposure` | Tier 1 | `error` (`critical_exposure`) | `ansible-vault/ansible-vault-exposure.yaml` | critical |
| `helm-values-exposure` | Tier 1 | `error` (`critical_exposure`) | `helm-values/helm-values-exposure.yaml` | critical |
| `pip-config-exposure` | Tier 1 | `error` (`critical_exposure`) | `pip-config/pip-config-exposure.yaml` | critical |
| `pypi-token-exposure` | Tier 1 | `error` (`critical_exposure`) | `pypi-token/pypi-token-exposure.yaml` | critical |
| `nuget-key-exposure` | Tier 1 | `error` (`critical_exposure`) | `nuget-key/nuget-key-exposure.yaml` | critical |
| `cargo-token-exposure` | Tier 1 | `error` (`critical_exposure`) | `cargo-token/cargo-token-exposure.yaml` | critical |
| `netrc-credentials-exposure` | Tier 1 | `error` (`critical_exposure`) | `netrc-credentials/netrc-credentials-exposure.yaml` | critical |
| `pgpass-exposure` | Tier 1 | `error` (`critical_exposure`) | `pgpass/pgpass-exposure.yaml` | critical |
| `database-url-exposure` | Tier 1 | `error` (`critical_exposure`) | `database-url/database-url-exposure.yaml` | critical |
| `mongodb-uri-exposure` | Tier 1 | `error` (`critical_exposure`) | `mongodb-uri/mongodb-uri-exposure.yaml` | critical |
| `redis-config-exposure` | Tier 1 | `error` (`critical_exposure`) | `redis-config/redis-config-exposure.yaml` | critical |
| `firebase-config-exposure` | Tier 1 | `error` (`critical_exposure`) | `firebase-config/firebase-config-exposure.yaml` | critical |
| `sentry-dsn-exposure` | Tier 1 | `error` (`critical_exposure`) | `sentry-dsn/sentry-dsn-exposure.yaml` | high |
| `datadog-key-exposure` | Tier 1 | `error` (`critical_exposure`) | `datadog-key/datadog-key-exposure.yaml` | critical |
| `caddy-admin-exposure` | Tier 1 | `error` (`critical_exposure`) | `caddy-admin/caddy-admin-exposure.yaml` | critical |
| `traefik-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `traefik-api/traefik-api-exposure.yaml` | critical |
| `nginx-status-exposure` | Tier 1 | `error` (`critical_exposure`) | `nginx-status/nginx-status-exposure.yaml` | high |
| `haproxy-stats-exposure` | Tier 1 | `error` (`critical_exposure`) | `haproxy-stats/haproxy-stats-exposure.yaml` | high |
| `envoy-admin-exposure` | Tier 1 | `error` (`critical_exposure`) | `envoy-admin/envoy-admin-exposure.yaml` | critical |
| `istio-debug-exposure` | Tier 1 | `error` (`critical_exposure`) | `istio-debug/istio-debug-exposure.yaml` | critical |
| `zookeeper-admin-exposure` | Tier 1 | `error` (`critical_exposure`) | `zookeeper-admin/zookeeper-admin-exposure.yaml` | critical |
| `kafka-rest-exposure` | Tier 1 | `error` (`critical_exposure`) | `kafka-rest/kafka-rest-exposure.yaml` | critical |
| `kafka-ui-exposure` | Tier 1 | `error` (`critical_exposure`) | `kafka-ui/kafka-ui-exposure.yaml` | high |
| `argo-cd-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `argo-cd/argo-cd-api-exposure.yaml` | critical |
| `spinnaker-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `spinnaker/spinnaker-api-exposure.yaml` | critical |
| `tekton-dashboard-exposure` | Tier 1 | `error` (`critical_exposure`) | `tekton/tekton-dashboard-exposure.yaml` | high |
| `drone-ci-exposure` | Tier 1 | `error` (`critical_exposure`) | `drone-ci/drone-ci-exposure.yaml` | critical |
| `teamcity-server-exposure` | Tier 1 | `error` (`critical_exposure`) | `teamcity-server/teamcity-server-exposure.yaml` | critical |
| `bamboo-server-exposure` | Tier 1 | `error` (`critical_exposure`) | `bamboo-server/bamboo-server-exposure.yaml` | critical |
| `sonarqube-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `sonarqube-api/sonarqube-api-exposure.yaml` | high |
| `nexus-repository-exposure` | Tier 1 | `error` (`critical_exposure`) | `nexus-repository/nexus-repository-exposure.yaml` | critical |
| `artifactory-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `artifactory/artifactory-api-exposure.yaml` | critical |
| `harbor-registry-exposure` | Tier 1 | `error` (`critical_exposure`) | `harbor-registry/harbor-registry-exposure.yaml` | critical |
| `keycloak-admin-exposure` | Tier 1 | `error` (`critical_exposure`) | `keycloak-admin/keycloak-admin-exposure.yaml` | critical |
| `airflow-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `airflow-api/airflow-api-exposure.yaml` | critical |
| `superset-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `superset-api/superset-api-exposure.yaml` | critical |
| `metabase-api-exposure` | Tier 1 | `error` (`critical_exposure`) | `metabase-api/metabase-api-exposure.yaml` | critical |
| `oauth-well-known-exposure` | Tier 1 | `error` (`critical_exposure`) | `oauth-well-known/oauth-well-known-exposure.yaml` | high |
| `oidc-config-exposure` | Tier 1 | `error` (`critical_exposure`) | `oidc-config/oidc-config-exposure.yaml` | high |
| `registry-catalog-exposure` | Tier 1 | `error` (`critical_exposure`) | `registry-catalog/registry-catalog-exposure.yaml` | critical |

### Native PoC (Tier 3)

| Plugin | Tier | Oracle | File |
|--------|------|--------|------|
| `poc-native-header-check` | Tier 3 | `header` | `native/poc-native-header-check.gashplugin.yaml` |

---

## Testing

```sh
# Single plugin (YAML)
go run ./cmd/gash plugins test plugins/headers/missing-security-headers.yaml

# Single plugin (JS)
go run ./cmd/gash plugins test plugins/xss/xss-reflected-basic.js

# All plugins metric gate
go test ./tests/plugins/ -run TestMetricGate -v

# Corpus no-false-positives
go test ./tests/corpus/ -run TestNoFalsePositives -v
```

### Fixture Structure

```
tests/fixtures/<plugin-id>/
├── positive/
│   ├── positive_01.json
│   └── ...
├── negative/
│   ├── negative_01.json
│   └── ...
└── ambiguous/          # optional
    └── ambiguous_01.json
```

Each fixture JSON:
```json
{
  "body": "<html>...</html>",
  "control_body": "<html>clean</html>",
  "control_status": 200,
  "expected_verdict": "accept|reject",
  "expected_confidence": "tentative|firm|confirmed",
  "headers": { "Content-Type": "text/html" },
  "name": "Descriptive name",
  "status": 200,
  "target": "http://example.com/?param=payload"
}
```

---

## Engine-recon (No Plugin File)

These ship as engine-internal detectors, not Tier 1 plugins:

| Detector | Package | GASH-ID | Test Command |
|----------|---------|---------|--------------|
| Content Discovery | `internal/discovery` | GASH-028 | `go test ./internal/discovery/ -run 'TestContentDiscovery\|TestWordlist' -v` |
| SPA State Secrets | `internal/discovery/spa_state.go` | GASH-071 | `go test ./internal/discovery/ -run TestSPAState -v` |
| Dev Build Markers | `internal/discovery/devbuild.go` | GASH-072 | `go test ./internal/discovery/ -run TestDevBuild -v` |
| Request Smuggling | `internal/smuggle` | GASH-033 | `go test ./internal/smuggle/ -v` |

Reports: `docs/metrics/content-discovery-2026-10-16.md`, `docs/metrics/smuggle-differential.md`.

---

## Adding a Plugin

1. **Choose category** — create dir under `plugins/<category>/` if needed
2. **Scaffold** — `go run ./cmd/gash plugins new my-check --tier yaml` (or `--tier js`)
3. **Point tests** — `tests: tests/fixtures/my-check/` with `positive/`, `negative/`
4. **Add metrics doc** — `docs/metrics/my-check.md` (follow `docs/metrics/README.md`)
5. **Run metric gate** — `go test ./tests/plugins/ -run TestMetricGate/my-check`
6. **Update this index** — add row to category table above
7. **Open PR** — fill PR template, include fixture test output

### Good First Contribution Labels

Look for ⭐ **Yes** in tables above. These plugins:
- Use simple Tier 1 YAML
- Have clear oracle mapping (header/error/redirect)
- Need minimal logic (single-request + single-oracle)
- Fixture structure already established

---

## Tier 3 Trust (Native Plugins)

Native binaries **never run on discovery alone**. Required:

1. Build plugin binary
2. Compute SHA256
3. `gash plugins trust ./my-plugin --sha256 <hash>`
4. Store approval in `~/.gash/trust.db` (auto-migrated from legacy `trust.json`)
5. Run with `--strict-plugins` to only execute trusted Tier 3

Reference pin: `plugins/native/poc-native-header-check.gashplugin.yaml`
