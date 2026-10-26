<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/README.md
What: Index of per-plugin precision and recall reports.
Why: Keeps the 99 percent precision gate auditable in one place.
-->

# Metrics Reports

## Purpose

Each reference plugin ships a precision and recall report under this directory.
A plugin lands only when its fixtures pass and precision stays at or above 99 percent.
The gate is enforced by `TestMetricGate` in `tests/plugins`, not by review convention.

## Contents

| Plugin | Report |
|---|---|
| missing-security-headers | [missing-security-headers.md](missing-security-headers.md) |
| cookie-flags | [cookie-flags.md](cookie-flags.md) |
| cors-misconfig | [cors-misconfig.md](cors-misconfig.md) |
| open-redirect-param | [open-redirect-param.md](open-redirect-param.md) |
| xss-reflected-basic | [xss-reflected-basic.md](xss-reflected-basic.md) |
| sqli-error-based | [sqli-error-based.md](sqli-error-based.md) |
| sqli-boolean-differential | [sqli-boolean-differential.md](sqli-boolean-differential.md) |
| ssrf-blind-oob | [ssrf-blind-oob.md](ssrf-blind-oob.md) |
| poc-native-header-check | [poc-native-header-check.md](poc-native-header-check.md) |
| sqli-auth-bypass | [sqli-auth-bypass.md](sqli-auth-bypass.md) |
| sqli-stacked-time | [sqli-stacked-time.md](sqli-stacked-time.md) |
| ssrf-cloud-metadata | [ssrf-cloud-metadata.md](ssrf-cloud-metadata.md) |
| xss-attribute-injection | [xss-attribute-injection.md](xss-attribute-injection.md) |
| dom-sink-basic | [dom-sink-basic.md](dom-sink-basic.md) |
| command-injection-timing | [command-injection-timing.md](command-injection-timing.md) |
| xss-stored-basic | [xss-stored-basic.md](xss-stored-basic.md) |
| xxe-reflected-basic | [xxe-reflected-basic.md](xxe-reflected-basic.md) |
| csrf-token-absence | [csrf-token-absence.md](csrf-token-absence.md) |
| clickjacking-frameable | [clickjacking-frameable.md](clickjacking-frameable.md) |
| hpp-parameter-pollution | [hpp-parameter-pollution.md](hpp-parameter-pollution.md) |
| hpp-duplicate-emission | [hpp-duplicate-emission.md](hpp-duplicate-emission.md) |
| hpp-json-duplicate-keys | [hpp-json-duplicate-keys.md](hpp-json-duplicate-keys.md) |
| hpp-multipart-duplicate-keys | [hpp-multipart-duplicate-keys.md](hpp-multipart-duplicate-keys.md) |
| sqli-json-body-error | [sqli-json-body-error.md](sqli-json-body-error.md) |
| sqli-json-body-differential | [sqli-json-body-differential.md](sqli-json-body-differential.md) |
| sqli-second-order | [sqli-second-order.md](sqli-second-order.md) |
| sqli-second-order-timing | [sqli-second-order-timing.md](sqli-second-order-timing.md) |
| open-redirect-json-body | [open-redirect-json-body.md](open-redirect-json-body.md) |
| xss-reflected-json-body | [xss-reflected-json-body.md](xss-reflected-json-body.md) |
| xss-stored-json-api | [xss-stored-json-api.md](xss-stored-json-api.md) |
| command-injection-json-body-oob | [command-injection-json-body-oob.md](command-injection-json-body-oob.md) |
| ssrf-json-body-oob | [ssrf-json-body-oob.md](ssrf-json-body-oob.md) |
| lfi-json-body | [lfi-json-body.md](lfi-json-body.md) |
| graphql-batch-abuse | [graphql-batch-abuse.md](graphql-batch-abuse.md) |
| file-upload-served | [file-upload-served.md](file-upload-served.md) |
| xxe-json-body-oob | [xxe-json-body-oob.md](xxe-json-body-oob.md) |
| insecure-cors-reflected-origin | [insecure-cors-reflected-origin.md](insecure-cors-reflected-origin.md) |
| ldap-injection-json-body | [ldap-injection-json-body.md](ldap-injection-json-body.md) |
| insecure-deserialization-json-body | [insecure-deserialization-json-body.md](insecure-deserialization-json-body.md) |
| sqli-json-body-timing | [sqli-json-body-timing.md](sqli-json-body-timing.md) |
| nosql-injection-timing-json-body | [nosql-injection-timing-json-body.md](nosql-injection-timing-json-body.md) |
| nosql-injection-differential-json-body | [nosql-injection-differential-json-body.md](nosql-injection-differential-json-body.md) |
| xpath-injection-json-body | [xpath-injection-json-body.md](xpath-injection-json-body.md) |
| jwt-none-alg-bypass | [jwt-none-alg-bypass.md](jwt-none-alg-bypass.md) |
| web-cache-method-override | [web-cache-method-override.md](web-cache-method-override.md) |
| web-cache-unkeyed-header | [web-cache-unkeyed-header.md](web-cache-unkeyed-header.md) |
| xss-stored-two-step | [xss-stored-two-step.md](xss-stored-two-step.md) |
| rfi-remote-include | [rfi-remote-include.md](rfi-remote-include.md) |
| cve-dependency-scan | [cve-dependency-scan.md](cve-dependency-scan.md) |
| crlf-header-injection | [crlf-header-injection.md](crlf-header-injection.md) |
| path-traversal-error | [path-traversal-error.md](path-traversal-error.md) |
| error-message-disclosure | [error-message-disclosure.md](error-message-disclosure.md) |
| jwt-token-exposure | [jwt-token-exposure.md](jwt-token-exposure.md) |
| jwt-alg-confusion | [jwt-alg-confusion.md](jwt-alg-confusion.md) |
| graphql-endpoint-discovery | [graphql-endpoint-discovery.md](graphql-endpoint-discovery.md) |
| file-upload-unrestricted | [file-upload-unrestricted.md](file-upload-unrestricted.md) |
| template-injection-reflection | [template-injection-reflection.md](template-injection-reflection.md) |
| xxe-oob | [xxe-oob.md](xxe-oob.md) |
| blind-sqli-oob | [blind-sqli-oob.md](blind-sqli-oob.md) |
| idor-differential | [idor-differential.md](idor-differential.md) |
| ldap-injection-differential | [ldap-injection-differential.md](ldap-injection-differential.md) |
| command-injection-error | [command-injection-error.md](command-injection-error.md) |
| server-version-disclosure | [server-version-disclosure.md](server-version-disclosure.md) |
| sqli-time-based | [sqli-time-based.md](sqli-time-based.md) |
| nosql-injection-error | [nosql-injection-error.md](nosql-injection-error.md) |
| web-cache-poisoning-basic | [web-cache-poisoning-basic.md](web-cache-poisoning-basic.md) |
| insecure-deserialization-error | [insecure-deserialization-error.md](insecure-deserialization-error.md) |
| subdomain-takeover-basic | [subdomain-takeover-basic.md](subdomain-takeover-basic.md) |
| mass-assignment-basic | [mass-assignment-basic.md](mass-assignment-basic.md) |
| missing-rate-limit | [missing-rate-limit.md](missing-rate-limit.md) |
| xpath-injection-error | [xpath-injection-error.md](xpath-injection-error.md) |
| host-header-injection | [host-header-injection.md](host-header-injection.md) |
| verb-tampering-bypass | [verb-tampering-bypass.md](verb-tampering-bypass.md) |
| backup-file-exposure | [backup-file-exposure.md](backup-file-exposure.md) |
| graphql-introspection-enabled | [graphql-introspection-enabled.md](graphql-introspection-enabled.md) |
| nosql-auth-bypass-differential | [nosql-auth-bypass-differential.md](nosql-auth-bypass-differential.md) |
| phpinfo-exposure | [phpinfo-exposure.md](phpinfo-exposure.md) |
| management-endpoint-exposure | [management-endpoint-exposure.md](management-endpoint-exposure.md) |
| directory-listing | [directory-listing.md](directory-listing.md) |
| log4shell-jndi | [log4shell-jndi.md](log4shell-jndi.md) |
| expression-language-injection | [expression-language-injection.md](expression-language-injection.md) |
| jsonp-callback-injection | [jsonp-callback-injection.md](jsonp-callback-injection.md) |
| oauth-open-redirect | [oauth-open-redirect.md](oauth-open-redirect.md) |
| sqli-oob-second-order | [sqli-oob-second-order.md](sqli-oob-second-order.md) |
| ssti-json-body-oob | [ssti-json-body-oob.md](ssti-json-body-oob.md) |
| ldap-injection-oob-json-body | [ldap-injection-oob-json-body.md](ldap-injection-oob-json-body.md) |
| idor-sequential-id-matrix | [idor-sequential-id-matrix.md](idor-sequential-id-matrix.md) |
| mass-assignment-nested-json | [mass-assignment-nested-json.md](mass-assignment-nested-json.md) |
| graphql-alias-amplification | [graphql-alias-amplification.md](graphql-alias-amplification.md) |
| web-cache-unkeyed-cookie | [web-cache-unkeyed-cookie.md](web-cache-unkeyed-cookie.md) |
| command-injection-json-body-timing | [command-injection-json-body-timing.md](command-injection-json-body-timing.md) |
| file-upload-filename-traversal | [file-upload-filename-traversal.md](file-upload-filename-traversal.md) |
| cors-null-origin-trust | [cors-null-origin-trust.md](cors-null-origin-trust.md) |
| xss-reflected-url-context | [xss-reflected-url-context.md](xss-reflected-url-context.md) |
| xss-stored-header-two-step | [xss-stored-header-two-step.md](xss-stored-header-two-step.md) |
| open-redirect-userinfo-confusion | [open-redirect-userinfo-confusion.md](open-redirect-userinfo-confusion.md) |
| prototype-pollution-json-body | [prototype-pollution-json-body.md](prototype-pollution-json-body.md) |
| hpp-query-array-notation | [hpp-query-array-notation.md](hpp-query-array-notation.md) |
| ldap-injection-json-body-timing | [ldap-injection-json-body-timing.md](ldap-injection-json-body-timing.md) |
| xxe-json-body-error | [xxe-json-body-error.md](xxe-json-body-error.md) |
| command-injection-json-body-error | [command-injection-json-body-error.md](command-injection-json-body-error.md) |
| log4shell-json-body-oob | [log4shell-json-body-oob.md](log4shell-json-body-oob.md) |
| file-upload-sniffing-mismatch | [file-upload-sniffing-mismatch.md](file-upload-sniffing-mismatch.md) |

### Critical Control-Plane / Secret Exposure

| Plugin | Report |
|---|---|
| aws-credentials-exposure | [aws-credentials-exposure.md](aws-credentials-exposure.md) |
| npmrc-token-exposure | [npmrc-token-exposure.md](npmrc-token-exposure.md) |
| composer-auth-exposure | [composer-auth-exposure.md](composer-auth-exposure.md) |
| terraform-state-exposure | [terraform-state-exposure.md](terraform-state-exposure.md) |
| kubernetes-config-exposure | [kubernetes-config-exposure.md](kubernetes-config-exposure.md) |
| gitlab-runner-config-exposure | [gitlab-runner-config-exposure.md](gitlab-runner-config-exposure.md) |
| spring-config-exposure | [spring-config-exposure.md](spring-config-exposure.md) |
| vault-api-exposure | [vault-api-exposure.md](vault-api-exposure.md) |
| consul-api-exposure | [consul-api-exposure.md](consul-api-exposure.md) |
| etcd-api-exposure | [etcd-api-exposure.md](etcd-api-exposure.md) |
| docker-api-exposure | [docker-api-exposure.md](docker-api-exposure.md) |
| kubernetes-api-exposure | [kubernetes-api-exposure.md](kubernetes-api-exposure.md) |
| jenkins-script-console-exposure | [jenkins-script-console-exposure.md](jenkins-script-console-exposure.md) |
| jmx-console-exposure | [jmx-console-exposure.md](jmx-console-exposure.md) |
| solr-admin-exposure | [solr-admin-exposure.md](solr-admin-exposure.md) |
| elasticsearch-api-exposure | [elasticsearch-api-exposure.md](elasticsearch-api-exposure.md) |
| kibana-api-exposure | [kibana-api-exposure.md](kibana-api-exposure.md) |
| grafana-api-exposure | [grafana-api-exposure.md](grafana-api-exposure.md) |
| rabbitmq-management-exposure | [rabbitmq-management-exposure.md](rabbitmq-management-exposure.md) |
| jupyter-api-exposure | [jupyter-api-exposure.md](jupyter-api-exposure.md) |
| phpmyadmin-exposure | [phpmyadmin-exposure.md](phpmyadmin-exposure.md) |
| adminer-exposure | [adminer-exposure.md](adminer-exposure.md) |
| laravel-debug-exposure | [laravel-debug-exposure.md](laravel-debug-exposure.md) |
| django-debug-exposure | [django-debug-exposure.md](django-debug-exposure.md) |
| h2-console-exposure | [h2-console-exposure.md](h2-console-exposure.md) |
| saml-metadata-exposure | [saml-metadata-exposure.md](saml-metadata-exposure.md) |
| oauth-client-secret-exposure | [oauth-client-secret-exposure.md](oauth-client-secret-exposure.md) |
| github-actions-config-exposure | [github-actions-config-exposure.md](github-actions-config-exposure.md) |
| heapdump-exposure | [heapdump-exposure.md](heapdump-exposure.md) |
| minio-admin-exposure | [minio-admin-exposure.md](minio-admin-exposure.md) |

### Rare Cloud, Proxy, CI/CD, and Identity Exposure

| Plugin | Report |
|---|---|
| azure-credentials-exposure | [azure-credentials-exposure.md](azure-credentials-exposure.md) |
| gcp-service-account-exposure | [gcp-service-account-exposure.md](gcp-service-account-exposure.md) |
| digitalocean-token-exposure | [digitalocean-token-exposure.md](digitalocean-token-exposure.md) |
| slack-token-exposure | [slack-token-exposure.md](slack-token-exposure.md) |
| stripe-secret-exposure | [stripe-secret-exposure.md](stripe-secret-exposure.md) |
| twilio-token-exposure | [twilio-token-exposure.md](twilio-token-exposure.md) |
| sendgrid-key-exposure | [sendgrid-key-exposure.md](sendgrid-key-exposure.md) |
| private-key-exposure | [private-key-exposure.md](private-key-exposure.md) |
| ssh-private-key-exposure | [ssh-private-key-exposure.md](ssh-private-key-exposure.md) |
| jwt-secret-exposure | [jwt-secret-exposure.md](jwt-secret-exposure.md) |
| ansible-vault-exposure | [ansible-vault-exposure.md](ansible-vault-exposure.md) |
| helm-values-exposure | [helm-values-exposure.md](helm-values-exposure.md) |
| pip-config-exposure | [pip-config-exposure.md](pip-config-exposure.md) |
| pypi-token-exposure | [pypi-token-exposure.md](pypi-token-exposure.md) |
| nuget-key-exposure | [nuget-key-exposure.md](nuget-key-exposure.md) |
| cargo-token-exposure | [cargo-token-exposure.md](cargo-token-exposure.md) |
| netrc-credentials-exposure | [netrc-credentials-exposure.md](netrc-credentials-exposure.md) |
| pgpass-exposure | [pgpass-exposure.md](pgpass-exposure.md) |
| database-url-exposure | [database-url-exposure.md](database-url-exposure.md) |
| mongodb-uri-exposure | [mongodb-uri-exposure.md](mongodb-uri-exposure.md) |
| redis-config-exposure | [redis-config-exposure.md](redis-config-exposure.md) |
| firebase-config-exposure | [firebase-config-exposure.md](firebase-config-exposure.md) |
| sentry-dsn-exposure | [sentry-dsn-exposure.md](sentry-dsn-exposure.md) |
| datadog-key-exposure | [datadog-key-exposure.md](datadog-key-exposure.md) |
| caddy-admin-exposure | [caddy-admin-exposure.md](caddy-admin-exposure.md) |
| traefik-api-exposure | [traefik-api-exposure.md](traefik-api-exposure.md) |
| nginx-status-exposure | [nginx-status-exposure.md](nginx-status-exposure.md) |
| haproxy-stats-exposure | [haproxy-stats-exposure.md](haproxy-stats-exposure.md) |
| envoy-admin-exposure | [envoy-admin-exposure.md](envoy-admin-exposure.md) |
| istio-debug-exposure | [istio-debug-exposure.md](istio-debug-exposure.md) |
| zookeeper-admin-exposure | [zookeeper-admin-exposure.md](zookeeper-admin-exposure.md) |
| kafka-rest-exposure | [kafka-rest-exposure.md](kafka-rest-exposure.md) |
| kafka-ui-exposure | [kafka-ui-exposure.md](kafka-ui-exposure.md) |
| argo-cd-api-exposure | [argo-cd-api-exposure.md](argo-cd-api-exposure.md) |
| spinnaker-api-exposure | [spinnaker-api-exposure.md](spinnaker-api-exposure.md) |
| tekton-dashboard-exposure | [tekton-dashboard-exposure.md](tekton-dashboard-exposure.md) |
| drone-ci-exposure | [drone-ci-exposure.md](drone-ci-exposure.md) |
| teamcity-server-exposure | [teamcity-server-exposure.md](teamcity-server-exposure.md) |
| bamboo-server-exposure | [bamboo-server-exposure.md](bamboo-server-exposure.md) |
| sonarqube-api-exposure | [sonarqube-api-exposure.md](sonarqube-api-exposure.md) |
| nexus-repository-exposure | [nexus-repository-exposure.md](nexus-repository-exposure.md) |
| artifactory-api-exposure | [artifactory-api-exposure.md](artifactory-api-exposure.md) |
| harbor-registry-exposure | [harbor-registry-exposure.md](harbor-registry-exposure.md) |
| keycloak-admin-exposure | [keycloak-admin-exposure.md](keycloak-admin-exposure.md) |
| airflow-api-exposure | [airflow-api-exposure.md](airflow-api-exposure.md) |
| superset-api-exposure | [superset-api-exposure.md](superset-api-exposure.md) |
| metabase-api-exposure | [metabase-api-exposure.md](metabase-api-exposure.md) |
| oauth-well-known-exposure | [oauth-well-known-exposure.md](oauth-well-known-exposure.md) |
| oidc-config-exposure | [oidc-config-exposure.md](oidc-config-exposure.md) |
| registry-catalog-exposure | [registry-catalog-exposure.md](registry-catalog-exposure.md) |
| ssi-injection | [ssi-injection.md](ssi-injection.md) |
| webdav-enabled | [webdav-enabled.md](webdav-enabled.md) |
| source-map-exposure | [source-map-exposure.md](source-map-exposure.md) |
| nextjs-middleware-bypass | [nextjs-middleware-bypass.md](nextjs-middleware-bypass.md) |
| nextjs-image-optimizer-ssrf | [nextjs-image-optimizer-ssrf.md](nextjs-image-optimizer-ssrf.md) |
| caa-dns-check (proto GASH-027, unit-scoped) | [caa-dns-check.md](caa-dns-check.md) |
| content-discovery (engine-recon GASH-028, mock-fixture scoped) | [content-discovery-2026-10-16.md](content-discovery-2026-10-16.md) |
| smuggle-differential (engine-recon GASH-033, mock-fixture scoped) | [smuggle-differential.md](smuggle-differential.md) |

## Lab Reports

| Lab | Report |
|---|---|
| aggressive recall, localhost synthetic lab (2026-10-14) | [lab-aggressive-local-2026-10-14.md](lab-aggressive-local-2026-10-14.md) |
| native lab Juice Shop/DVWA/WebGoat (2026-10-20, measured; Gash standard/deep + Nuclei) | [native-lab-2026-10-20.md](native-lab-2026-10-20.md) |
| compose lab DVWA/Juice Shop (2026-10-14, BLOCKED: no docker) | [lab-compose-dvwa-juiceshop-2026-10-14.md](lab-compose-dvwa-juiceshop-2026-10-14.md) |
| compose lab DVWA/Juice Shop/WebGoat (2026-10-15, BLOCKED: no docker; native lab supersedes the measured subset) | [lab-compose-2026-10-15.md](lab-compose-2026-10-15.md) |
| Nuclei comparison (fixture lab 2026-10-19; native lab 2026-10-20) | [nuclei-comparison-2026-10-14.md](nuclei-comparison-2026-10-14.md) |
| benchmark, fixtures standard + deep (2026-10-19, measured; three recall fixes) | [benchmark-fixtures-2026-10-19.md](benchmark-fixtures-2026-10-19.md) |

## How to Reproduce

```sh
go test ./tests/plugins/ -run TestMetricGate -v
go run ./cmd/gash plugins test plugins/<category>/<file>
```

## Gate Rule

The reflected-XSS dataset is currently 10 fixtures (TP=2, FP=0, TN=8,
FN=0), pinned by its report hash. Fixture counts are not real-target recall.

Precision below 0.99 fails the build. Corpus `firm` plus findings fail the build.
Lab runs are manual and follow the procedure inside each report.

## Dataset Honesty (P0.3)

Per-plugin precision/recall numbers are fixture-scoped: small labelled sets
(1-6 cases per side), never real-world measurements. Each report pins its
fixture bytes under `## Dataset` (`Dataset hash`). `TestMetricGate` recomputes
the hash from `tests/fixtures/<id>/` on every run and fails when the report
drifts; silent fixture edits cannot inflate precision. Non-fixture lab
measurements are separate: the localhost synthetic lab and the 2026-10-20
native lab (Juice Shop/DVWA/WebGoat) above. The Docker compose procedure still
cannot run where no Docker runtime exists. Untested areas (multi-layer
encoding, browser-executed DOM discovery, timing under jitter, blind classes
without OOB) are named in the per-plugin report, never implied as covered.
