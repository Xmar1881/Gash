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
| actuator-index-exposure | [actuator-index-exposure.md](actuator-index-exposure.md) |
| adminer-exposure | [adminer-exposure.md](adminer-exposure.md) |
| airflow-api-exposure | [airflow-api-exposure.md](airflow-api-exposure.md) |
| ansible-vault-exposure | [ansible-vault-exposure.md](ansible-vault-exposure.md) |
| apollo-studio | [apollo-studio.md](apollo-studio.md) |
| argo-cd-api-exposure | [argo-cd-api-exposure.md](argo-cd-api-exposure.md) |
| artifactory-api-exposure | [artifactory-api-exposure.md](artifactory-api-exposure.md) |
| aws-credentials-exposure | [aws-credentials-exposure.md](aws-credentials-exposure.md) |
| azure-credentials-exposure | [azure-credentials-exposure.md](azure-credentials-exposure.md) |
| backup-file-exposure | [backup-file-exposure.md](backup-file-exposure.md) |
| bamboo-server-exposure | [bamboo-server-exposure.md](bamboo-server-exposure.md) |
| bind-stats | [bind-stats.md](bind-stats.md) |
| blind-sqli-oob | [blind-sqli-oob.md](blind-sqli-oob.md) |
| buildkite-agent | [buildkite-agent.md](buildkite-agent.md) |
| cache-poisoning-host-header | [cache-poisoning-host-header.md](cache-poisoning-host-header.md) |
| cacti-console | [cacti-console.md](cacti-console.md) |
| caddy-admin-exposure | [caddy-admin-exposure.md](caddy-admin-exposure.md) |
| calico-api | [calico-api.md](calico-api.md) |
| cargo-token-exposure | [cargo-token-exposure.md](cargo-token-exposure.md) |
| cassandra-jmx | [cassandra-jmx.md](cassandra-jmx.md) |
| ceph-dashboard | [ceph-dashboard.md](ceph-dashboard.md) |
| checkmk-console | [checkmk-console.md](checkmk-console.md) |
| cilium-hubble | [cilium-hubble.md](cilium-hubble.md) |
| circleci-server | [circleci-server.md](circleci-server.md) |
| clearml-server | [clearml-server.md](clearml-server.md) |
| clickhouse-http | [clickhouse-http.md](clickhouse-http.md) |
| clickjacking-frameable | [clickjacking-frameable.md](clickjacking-frameable.md) |
| cockpit-admin | [cockpit-admin.md](cockpit-admin.md) |
| cockroachdb-admin | [cockroachdb-admin.md](cockroachdb-admin.md) |
| coep-missing | [coep-missing.md](coep-missing.md) |
| command-injection-error | [command-injection-error.md](command-injection-error.md) |
| command-injection-json-body-error | [command-injection-json-body-error.md](command-injection-json-body-error.md) |
| command-injection-json-body-oob | [command-injection-json-body-oob.md](command-injection-json-body-oob.md) |
| command-injection-json-body-timing | [command-injection-json-body-timing.md](command-injection-json-body-timing.md) |
| command-injection-oob | [command-injection-oob.md](command-injection-oob.md) |
| command-injection-timing | [command-injection-timing.md](command-injection-timing.md) |
| composer-auth-exposure | [composer-auth-exposure.md](composer-auth-exposure.md) |
| consul-api-exposure | [consul-api-exposure.md](consul-api-exposure.md) |
| content-type-options-missing | [content-type-options-missing.md](content-type-options-missing.md) |
| cookie-flags | [cookie-flags.md](cookie-flags.md) |
| coop-missing | [coop-missing.md](coop-missing.md) |
| coredns-metrics | [coredns-metrics.md](coredns-metrics.md) |
| corp-missing | [corp-missing.md](corp-missing.md) |
| cors-misconfig | [cors-misconfig.md](cors-misconfig.md) |
| cors-null-origin-trust | [cors-null-origin-trust.md](cors-null-origin-trust.md) |
| couchdb-admin | [couchdb-admin.md](couchdb-admin.md) |
| crlf-header-injection | [crlf-header-injection.md](crlf-header-injection.md) |
| csp-unsafe-directives | [csp-unsafe-directives.md](csp-unsafe-directives.md) |
| csrf-token-absence | [csrf-token-absence.md](csrf-token-absence.md) |
| cve-dependency-scan | [cve-dependency-scan.md](cve-dependency-scan.md) |
| dagster-ui | [dagster-ui.md](dagster-ui.md) |
| database-url-exposure | [database-url-exposure.md](database-url-exposure.md) |
| datadog-key-exposure | [datadog-key-exposure.md](datadog-key-exposure.md) |
| debug-endpoint-exposure | [debug-endpoint-exposure.md](debug-endpoint-exposure.md) |
| debug-toolbar-exposure | [debug-toolbar-exposure.md](debug-toolbar-exposure.md) |
| dgraph-ratel | [dgraph-ratel.md](dgraph-ratel.md) |
| digitalocean-token-exposure | [digitalocean-token-exposure.md](digitalocean-token-exposure.md) |
| directory-listing | [directory-listing.md](directory-listing.md) |
| directus-admin | [directus-admin.md](directus-admin.md) |
| discourse-admin | [discourse-admin.md](discourse-admin.md) |
| django-debug-exposure | [django-debug-exposure.md](django-debug-exposure.md) |
| docker-api-exposure | [docker-api-exposure.md](docker-api-exposure.md) |
| docker-compose-exposure | [docker-compose-exposure.md](docker-compose-exposure.md) |
| dom-sink-basic | [dom-sink-basic.md](dom-sink-basic.md) |
| dovecot-status | [dovecot-status.md](dovecot-status.md) |
| drone-ci-exposure | [drone-ci-exposure.md](drone-ci-exposure.md) |
| elasticsearch-api-exposure | [elasticsearch-api-exposure.md](elasticsearch-api-exposure.md) |
| environment-file-exposure | [environment-file-exposure.md](environment-file-exposure.md) |
| envoy-admin-exposure | [envoy-admin-exposure.md](envoy-admin-exposure.md) |
| error-message-disclosure | [error-message-disclosure.md](error-message-disclosure.md) |
| etcd-api-exposure | [etcd-api-exposure.md](etcd-api-exposure.md) |
| expression-language-injection | [expression-language-injection.md](expression-language-injection.md) |
| feast-registry | [feast-registry.md](feast-registry.md) |
| file-inclusion-rfi | [file-inclusion-rfi.md](file-inclusion-rfi.md) |
| file-upload-filename-traversal | [file-upload-filename-traversal.md](file-upload-filename-traversal.md) |
| file-upload-served | [file-upload-served.md](file-upload-served.md) |
| file-upload-sniffing-mismatch | [file-upload-sniffing-mismatch.md](file-upload-sniffing-mismatch.md) |
| file-upload-unrestricted | [file-upload-unrestricted.md](file-upload-unrestricted.md) |
| filebrowser-admin | [filebrowser-admin.md](filebrowser-admin.md) |
| firebase-config-exposure | [firebase-config-exposure.md](firebase-config-exposure.md) |
| freeradius-debug | [freeradius-debug.md](freeradius-debug.md) |
| gcp-service-account-exposure | [gcp-service-account-exposure.md](gcp-service-account-exposure.md) |
| ghost-admin | [ghost-admin.md](ghost-admin.md) |
| git-config-exposure | [git-config-exposure.md](git-config-exposure.md) |
| gitbucket-admin | [gitbucket-admin.md](gitbucket-admin.md) |
| gitea-admin | [gitea-admin.md](gitea-admin.md) |
| github-actions-config-exposure | [github-actions-config-exposure.md](github-actions-config-exposure.md) |
| gitlab-runner-config-exposure | [gitlab-runner-config-exposure.md](gitlab-runner-config-exposure.md) |
| gogs-admin | [gogs-admin.md](gogs-admin.md) |
| grafana-api-exposure | [grafana-api-exposure.md](grafana-api-exposure.md) |
| graphql-alias-amplification | [graphql-alias-amplification.md](graphql-alias-amplification.md) |
| graphql-auth-bypass | [graphql-auth-bypass.md](graphql-auth-bypass.md) |
| graphql-batch-abuse | [graphql-batch-abuse.md](graphql-batch-abuse.md) |
| graphql-dos | [graphql-dos.md](graphql-dos.md) |
| graphql-endpoint-discovery | [graphql-endpoint-discovery.md](graphql-endpoint-discovery.md) |
| graphql-introspection-enabled | [graphql-introspection-enabled.md](graphql-introspection-enabled.md) |
| graphql-playground-exposure | [graphql-playground-exposure.md](graphql-playground-exposure.md) |
| graylog-api | [graylog-api.md](graylog-api.md) |
| h2-console-exposure | [h2-console-exposure.md](h2-console-exposure.md) |
| haproxy-stats-exposure | [haproxy-stats-exposure.md](haproxy-stats-exposure.md) |
| harbor-registry-exposure | [harbor-registry-exposure.md](harbor-registry-exposure.md) |
| hasura-console | [hasura-console.md](hasura-console.md) |
| heapdump-exposure | [heapdump-exposure.md](heapdump-exposure.md) |
| helm-values-exposure | [helm-values-exposure.md](helm-values-exposure.md) |
| host-header-injection | [host-header-injection.md](host-header-injection.md) |
| hpp-duplicate-emission | [hpp-duplicate-emission.md](hpp-duplicate-emission.md) |
| hpp-json-duplicate-keys | [hpp-json-duplicate-keys.md](hpp-json-duplicate-keys.md) |
| hpp-multipart-duplicate-keys | [hpp-multipart-duplicate-keys.md](hpp-multipart-duplicate-keys.md) |
| hpp-parameter-pollution | [hpp-parameter-pollution.md](hpp-parameter-pollution.md) |
| hpp-query-array-notation | [hpp-query-array-notation.md](hpp-query-array-notation.md) |
| hsts-hardening | [hsts-hardening.md](hsts-hardening.md) |
| http-method-override-abuse | [http-method-override-abuse.md](http-method-override-abuse.md) |
| http-response-splitting | [http-response-splitting.md](http-response-splitting.md) |
| icinga-web | [icinga-web.md](icinga-web.md) |
| idor-differential | [idor-differential.md](idor-differential.md) |
| idor-sequential-id-matrix | [idor-sequential-id-matrix.md](idor-sequential-id-matrix.md) |
| influxdb-api | [influxdb-api.md](influxdb-api.md) |
| insecure-cors-preflight | [insecure-cors-preflight.md](insecure-cors-preflight.md) |
| insecure-cors-reflected-origin | [insecure-cors-reflected-origin.md](insecure-cors-reflected-origin.md) |
| insecure-deserialization-error | [insecure-deserialization-error.md](insecure-deserialization-error.md) |
| insecure-deserialization-json-body | [insecure-deserialization-json-body.md](insecure-deserialization-json-body.md) |
| istio-debug-exposure | [istio-debug-exposure.md](istio-debug-exposure.md) |
| jaeger-query | [jaeger-query.md](jaeger-query.md) |
| jenkins-script-console-exposure | [jenkins-script-console-exposure.md](jenkins-script-console-exposure.md) |
| jmx-console-exposure | [jmx-console-exposure.md](jmx-console-exposure.md) |
| jsonp-callback-injection | [jsonp-callback-injection.md](jsonp-callback-injection.md) |
| jupyter-api-exposure | [jupyter-api-exposure.md](jupyter-api-exposure.md) |
| jupyterhub-admin | [jupyterhub-admin.md](jupyterhub-admin.md) |
| jwt-alg-confusion | [jwt-alg-confusion.md](jwt-alg-confusion.md) |
| jwt-none-alg-bypass | [jwt-none-alg-bypass.md](jwt-none-alg-bypass.md) |
| jwt-none-alg-confusion | [jwt-none-alg-confusion.md](jwt-none-alg-confusion.md) |
| jwt-secret-exposure | [jwt-secret-exposure.md](jwt-secret-exposure.md) |
| jwt-token-exposure | [jwt-token-exposure.md](jwt-token-exposure.md) |
| kafka-rest-exposure | [kafka-rest-exposure.md](kafka-rest-exposure.md) |
| kafka-ui-exposure | [kafka-ui-exposure.md](kafka-ui-exposure.md) |
| keycloak-admin-exposure | [keycloak-admin-exposure.md](keycloak-admin-exposure.md) |
| keydb-admin | [keydb-admin.md](keydb-admin.md) |
| keystone-admin | [keystone-admin.md](keystone-admin.md) |
| kiali-console | [kiali-console.md](kiali-console.md) |
| kibana-api-exposure | [kibana-api-exposure.md](kibana-api-exposure.md) |
| kong-admin | [kong-admin.md](kong-admin.md) |
| kubeflow-dashboard | [kubeflow-dashboard.md](kubeflow-dashboard.md) |
| kubernetes-api-exposure | [kubernetes-api-exposure.md](kubernetes-api-exposure.md) |
| kubernetes-config-exposure | [kubernetes-config-exposure.md](kubernetes-config-exposure.md) |
| laravel-debug-exposure | [laravel-debug-exposure.md](laravel-debug-exposure.md) |
| ldap-injection-blind | [ldap-injection-blind.md](ldap-injection-blind.md) |
| ldap-injection-differential | [ldap-injection-differential.md](ldap-injection-differential.md) |
| ldap-injection-json-body | [ldap-injection-json-body.md](ldap-injection-json-body.md) |
| ldap-injection-json-body-timing | [ldap-injection-json-body-timing.md](ldap-injection-json-body-timing.md) |
| ldap-injection-oob | [ldap-injection-oob.md](ldap-injection-oob.md) |
| ldap-injection-oob-json-body | [ldap-injection-oob-json-body.md](ldap-injection-oob-json-body.md) |
| lfi-json-body | [lfi-json-body.md](lfi-json-body.md) |
| log4shell-jndi | [log4shell-jndi.md](log4shell-jndi.md) |
| log4shell-json-body-oob | [log4shell-json-body-oob.md](log4shell-json-body-oob.md) |
| loki-api | [loki-api.md](loki-api.md) |
| longhorn-ui | [longhorn-ui.md](longhorn-ui.md) |
| mailhog-ui | [mailhog-ui.md](mailhog-ui.md) |
| management-endpoint-exposure | [management-endpoint-exposure.md](management-endpoint-exposure.md) |
| mantisbt-admin | [mantisbt-admin.md](mantisbt-admin.md) |
| mass-assignment-basic | [mass-assignment-basic.md](mass-assignment-basic.md) |
| mass-assignment-nested-json | [mass-assignment-nested-json.md](mass-assignment-nested-json.md) |
| mattermost-admin | [mattermost-admin.md](mattermost-admin.md) |
| medusa-admin | [medusa-admin.md](medusa-admin.md) |
| memcached-stats | [memcached-stats.md](memcached-stats.md) |
| metabase-api-exposure | [metabase-api-exposure.md](metabase-api-exposure.md) |
| metallb-controller | [metallb-controller.md](metallb-controller.md) |
| miniflux-admin | [miniflux-admin.md](miniflux-admin.md) |
| minio-admin-exposure | [minio-admin-exposure.md](minio-admin-exposure.md) |
| missing-rate-limit | [missing-rate-limit.md](missing-rate-limit.md) |
| missing-security-headers | [missing-security-headers.md](missing-security-headers.md) |
| mlflow-tracking | [mlflow-tracking.md](mlflow-tracking.md) |
| mongodb-uri-exposure | [mongodb-uri-exposure.md](mongodb-uri-exposure.md) |
| n8n-editor | [n8n-editor.md](n8n-editor.md) |
| nagios-cgi | [nagios-cgi.md](nagios-cgi.md) |
| neo4j-browser | [neo4j-browser.md](neo4j-browser.md) |
| netdata-dashboard | [netdata-dashboard.md](netdata-dashboard.md) |
| netrc-credentials-exposure | [netrc-credentials-exposure.md](netrc-credentials-exposure.md) |
| nextcloud-status | [nextcloud-status.md](nextcloud-status.md) |
| nextjs-image-optimizer-ssrf | [nextjs-image-optimizer-ssrf.md](nextjs-image-optimizer-ssrf.md) |
| nextjs-middleware-bypass | [nextjs-middleware-bypass.md](nextjs-middleware-bypass.md) |
| nexus-repository-exposure | [nexus-repository-exposure.md](nexus-repository-exposure.md) |
| nginx-status-exposure | [nginx-status-exposure.md](nginx-status-exposure.md) |
| nosql-auth-bypass-differential | [nosql-auth-bypass-differential.md](nosql-auth-bypass-differential.md) |
| nosql-injection-differential-json-body | [nosql-injection-differential-json-body.md](nosql-injection-differential-json-body.md) |
| nosql-injection-error | [nosql-injection-error.md](nosql-injection-error.md) |
| nosql-injection-timing | [nosql-injection-timing.md](nosql-injection-timing.md) |
| nosql-injection-timing-json-body | [nosql-injection-timing-json-body.md](nosql-injection-timing-json-body.md) |
| nosql-nested-json-operator | [nosql-nested-json-operator.md](nosql-nested-json-operator.md) |
| npmrc-token-exposure | [npmrc-token-exposure.md](npmrc-token-exposure.md) |
| nuget-key-exposure | [nuget-key-exposure.md](nuget-key-exposure.md) |
| oauth-client-secret-exposure | [oauth-client-secret-exposure.md](oauth-client-secret-exposure.md) |
| oauth-open-redirect | [oauth-open-redirect.md](oauth-open-redirect.md) |
| oauth-well-known-exposure | [oauth-well-known-exposure.md](oauth-well-known-exposure.md) |
| oidc-config-exposure | [oidc-config-exposure.md](oidc-config-exposure.md) |
| open-redirect-json-body | [open-redirect-json-body.md](open-redirect-json-body.md) |
| open-redirect-param | [open-redirect-param.md](open-redirect-param.md) |
| open-redirect-path-parser | [open-redirect-path-parser.md](open-redirect-path-parser.md) |
| open-redirect-userinfo-confusion | [open-redirect-userinfo-confusion.md](open-redirect-userinfo-confusion.md) |
| openapi-spec-exposure | [openapi-spec-exposure.md](openapi-spec-exposure.md) |
| openfga-api | [openfga-api.md](openfga-api.md) |
| openproject-admin | [openproject-admin.md](openproject-admin.md) |
| openresty-status | [openresty-status.md](openresty-status.md) |
| openstack-horizon | [openstack-horizon.md](openstack-horizon.md) |
| openvpn-status | [openvpn-status.md](openvpn-status.md) |
| otel-collector-debug | [otel-collector-debug.md](otel-collector-debug.md) |
| owncloud-status | [owncloud-status.md](owncloud-status.md) |
| path-traversal-encoding-bypass | [path-traversal-encoding-bypass.md](path-traversal-encoding-bypass.md) |
| path-traversal-error | [path-traversal-error.md](path-traversal-error.md) |
| payload-cms-admin | [payload-cms-admin.md](payload-cms-admin.md) |
| permissions-policy-missing | [permissions-policy-missing.md](permissions-policy-missing.md) |
| pgadmin-console | [pgadmin-console.md](pgadmin-console.md) |
| pgpass-exposure | [pgpass-exposure.md](pgpass-exposure.md) |
| pgweb-console | [pgweb-console.md](pgweb-console.md) |
| phabricator-api | [phabricator-api.md](phabricator-api.md) |
| phpinfo-exposure | [phpinfo-exposure.md](phpinfo-exposure.md) |
| phpmyadmin-exposure | [phpmyadmin-exposure.md](phpmyadmin-exposure.md) |
| pip-config-exposure | [pip-config-exposure.md](pip-config-exposure.md) |
| plane-admin | [plane-admin.md](plane-admin.md) |
| poc-native-header-check | [poc-native-header-check.md](poc-native-header-check.md) |
| pocketbase-admin | [pocketbase-admin.md](pocketbase-admin.md) |
| portainer-api | [portainer-api.md](portainer-api.md) |
| postfix-admin | [postfix-admin.md](postfix-admin.md) |
| powerdns-api | [powerdns-api.md](powerdns-api.md) |
| powered-by-disclosure | [powered-by-disclosure.md](powered-by-disclosure.md) |
| prefect-server | [prefect-server.md](prefect-server.md) |
| private-key-exposure | [private-key-exposure.md](private-key-exposure.md) |
| prometheus-metrics-exposure | [prometheus-metrics-exposure.md](prometheus-metrics-exposure.md) |
| prototype-pollution-differential | [prototype-pollution-differential.md](prototype-pollution-differential.md) |
| prototype-pollution-json-body | [prototype-pollution-json-body.md](prototype-pollution-json-body.md) |
| proxmox-api | [proxmox-api.md](proxmox-api.md) |
| pypi-token-exposure | [pypi-token-exposure.md](pypi-token-exposure.md) |
| rabbitmq-management-exposure | [rabbitmq-management-exposure.md](rabbitmq-management-exposure.md) |
| rancher-api | [rancher-api.md](rancher-api.md) |
| ray-dashboard | [ray-dashboard.md](ray-dashboard.md) |
| redis-config-exposure | [redis-config-exposure.md](redis-config-exposure.md) |
| redmine-admin | [redmine-admin.md](redmine-admin.md) |
| referrer-policy-missing | [referrer-policy-missing.md](referrer-policy-missing.md) |
| registry-catalog-exposure | [registry-catalog-exposure.md](registry-catalog-exposure.md) |
| reviewboard-admin | [reviewboard-admin.md](reviewboard-admin.md) |
| rfi-remote-include | [rfi-remote-include.md](rfi-remote-include.md) |
| rocket-chat-admin | [rocket-chat-admin.md](rocket-chat-admin.md) |
| rstudio-connect | [rstudio-connect.md](rstudio-connect.md) |
| saleor-dashboard | [saleor-dashboard.md](saleor-dashboard.md) |
| saml-metadata-exposure | [saml-metadata-exposure.md](saml-metadata-exposure.md) |
| seafile-admin | [seafile-admin.md](seafile-admin.md) |
| security-txt-exposure | [security-txt-exposure.md](security-txt-exposure.md) |
| seldon-core | [seldon-core.md](seldon-core.md) |
| sendgrid-key-exposure | [sendgrid-key-exposure.md](sendgrid-key-exposure.md) |
| sensitive-file-exposure | [sensitive-file-exposure.md](sensitive-file-exposure.md) |
| sentry-dsn-exposure | [sentry-dsn-exposure.md](sentry-dsn-exposure.md) |
| server-header-disclosure | [server-header-disclosure.md](server-header-disclosure.md) |
| server-version-disclosure | [server-version-disclosure.md](server-version-disclosure.md) |
| shiny-server | [shiny-server.md](shiny-server.md) |
| slack-token-exposure | [slack-token-exposure.md](slack-token-exposure.md) |
| smtp4dev-ui | [smtp4dev-ui.md](smtp4dev-ui.md) |
| snipe-it-admin | [snipe-it-admin.md](snipe-it-admin.md) |
| solr-admin-exposure | [solr-admin-exposure.md](solr-admin-exposure.md) |
| sonarqube-api-exposure | [sonarqube-api-exposure.md](sonarqube-api-exposure.md) |
| source-map-exposure | [source-map-exposure.md](source-map-exposure.md) |
| spinnaker-api-exposure | [spinnaker-api-exposure.md](spinnaker-api-exposure.md) |
| spring-config-exposure | [spring-config-exposure.md](spring-config-exposure.md) |
| sqli-auth-bypass | [sqli-auth-bypass.md](sqli-auth-bypass.md) |
| sqli-boolean-differential | [sqli-boolean-differential.md](sqli-boolean-differential.md) |
| sqli-error-based | [sqli-error-based.md](sqli-error-based.md) |
| sqli-json-body-differential | [sqli-json-body-differential.md](sqli-json-body-differential.md) |
| sqli-json-body-error | [sqli-json-body-error.md](sqli-json-body-error.md) |
| sqli-json-body-timing | [sqli-json-body-timing.md](sqli-json-body-timing.md) |
| sqli-multipart-error | [sqli-multipart-error.md](sqli-multipart-error.md) |
| sqli-oob-second-order | [sqli-oob-second-order.md](sqli-oob-second-order.md) |
| sqli-second-order | [sqli-second-order.md](sqli-second-order.md) |
| sqli-second-order-timing | [sqli-second-order-timing.md](sqli-second-order-timing.md) |
| sqli-stacked-time | [sqli-stacked-time.md](sqli-stacked-time.md) |
| sqli-time-based | [sqli-time-based.md](sqli-time-based.md) |
| sqli-xml-body-error | [sqli-xml-body-error.md](sqli-xml-body-error.md) |
| sqlpad-console | [sqlpad-console.md](sqlpad-console.md) |
| squid-cache | [squid-cache.md](squid-cache.md) |
| ssh-private-key-exposure | [ssh-private-key-exposure.md](ssh-private-key-exposure.md) |
| ssi-injection | [ssi-injection.md](ssi-injection.md) |
| ssrf-blind-oob | [ssrf-blind-oob.md](ssrf-blind-oob.md) |
| ssrf-cloud-metadata | [ssrf-cloud-metadata.md](ssrf-cloud-metadata.md) |
| ssrf-internal-port-scan | [ssrf-internal-port-scan.md](ssrf-internal-port-scan.md) |
| ssrf-json-body-oob | [ssrf-json-body-oob.md](ssrf-json-body-oob.md) |
| ssti-blind-oob | [ssti-blind-oob.md](ssti-blind-oob.md) |
| ssti-blind-timing | [ssti-blind-timing.md](ssti-blind-timing.md) |
| ssti-json-body-oob | [ssti-json-body-oob.md](ssti-json-body-oob.md) |
| strapi-admin | [strapi-admin.md](strapi-admin.md) |
| stripe-secret-exposure | [stripe-secret-exposure.md](stripe-secret-exposure.md) |
| subdomain-takeover-basic | [subdomain-takeover-basic.md](subdomain-takeover-basic.md) |
| supabase-studio | [supabase-studio.md](supabase-studio.md) |
| superset-api-exposure | [superset-api-exposure.md](superset-api-exposure.md) |
| swagger-ui-exposure | [swagger-ui-exposure.md](swagger-ui-exposure.md) |
| syncthing-gui | [syncthing-gui.md](syncthing-gui.md) |
| teamcity-server-exposure | [teamcity-server-exposure.md](teamcity-server-exposure.md) |
| tekton-dashboard-exposure | [tekton-dashboard-exposure.md](tekton-dashboard-exposure.md) |
| template-injection-reflection | [template-injection-reflection.md](template-injection-reflection.md) |
| terraform-state-exposure | [terraform-state-exposure.md](terraform-state-exposure.md) |
| timescaledb-admin | [timescaledb-admin.md](timescaledb-admin.md) |
| traefik-api-exposure | [traefik-api-exposure.md](traefik-api-exposure.md) |
| twilio-token-exposure | [twilio-token-exposure.md](twilio-token-exposure.md) |
| unbound-control | [unbound-control.md](unbound-control.md) |
| varnish-status | [varnish-status.md](varnish-status.md) |
| vault-api-exposure | [vault-api-exposure.md](vault-api-exposure.md) |
| verb-tampering-bypass | [verb-tampering-bypass.md](verb-tampering-bypass.md) |
| vitess-vtgate | [vitess-vtgate.md](vitess-vtgate.md) |
| wasmcloud-host | [wasmcloud-host.md](wasmcloud-host.md) |
| web-cache-method-override | [web-cache-method-override.md](web-cache-method-override.md) |
| web-cache-poisoning-basic | [web-cache-poisoning-basic.md](web-cache-poisoning-basic.md) |
| web-cache-unkeyed-cookie | [web-cache-unkeyed-cookie.md](web-cache-unkeyed-cookie.md) |
| web-cache-unkeyed-header | [web-cache-unkeyed-header.md](web-cache-unkeyed-header.md) |
| webdav-enabled | [webdav-enabled.md](webdav-enabled.md) |
| webmin-admin | [webmin-admin.md](webmin-admin.md) |
| wireguard-config | [wireguard-config.md](wireguard-config.md) |
| xml-external-entity-blind | [xml-external-entity-blind.md](xml-external-entity-blind.md) |
| xpath-injection-error | [xpath-injection-error.md](xpath-injection-error.md) |
| xpath-injection-json-body | [xpath-injection-json-body.md](xpath-injection-json-body.md) |
| xpath-xml-body-error | [xpath-xml-body-error.md](xpath-xml-body-error.md) |
| xss-attribute-injection | [xss-attribute-injection.md](xss-attribute-injection.md) |
| xss-path-segment | [xss-path-segment.md](xss-path-segment.md) |
| xss-reflected-basic | [xss-reflected-basic.md](xss-reflected-basic.md) |
| xss-reflected-header | [xss-reflected-header.md](xss-reflected-header.md) |
| xss-reflected-json-body | [xss-reflected-json-body.md](xss-reflected-json-body.md) |
| xss-reflected-url-context | [xss-reflected-url-context.md](xss-reflected-url-context.md) |
| xss-stored-basic | [xss-stored-basic.md](xss-stored-basic.md) |
| xss-stored-header-two-step | [xss-stored-header-two-step.md](xss-stored-header-two-step.md) |
| xss-stored-json-api | [xss-stored-json-api.md](xss-stored-json-api.md) |
| xss-stored-two-step | [xss-stored-two-step.md](xss-stored-two-step.md) |
| xxe-blind-oob | [xxe-blind-oob.md](xxe-blind-oob.md) |
| xxe-json-body-error | [xxe-json-body-error.md](xxe-json-body-error.md) |
| xxe-json-body-oob | [xxe-json-body-oob.md](xxe-json-body-oob.md) |
| xxe-oob | [xxe-oob.md](xxe-oob.md) |
| xxe-reflected-basic | [xxe-reflected-basic.md](xxe-reflected-basic.md) |
| xxe-svg-upload-oob | [xxe-svg-upload-oob.md](xxe-svg-upload-oob.md) |
| xxe-xml-body-oob | [xxe-xml-body-oob.md](xxe-xml-body-oob.md) |
| youtrack-admin | [youtrack-admin.md](youtrack-admin.md) |
| zabbix-api | [zabbix-api.md](zabbix-api.md) |
| zipkin-api | [zipkin-api.md](zipkin-api.md) |
| zookeeper-admin-exposure | [zookeeper-admin-exposure.md](zookeeper-admin-exposure.md) |
| zulip-server | [zulip-server.md](zulip-server.md) |

## Lab Reports

| Lab | Report |
|---|---|
| aggressive recall, localhost synthetic lab (2026-10-14) | [lab-aggressive-local-2026-10-14.md](lab-aggressive-local-2026-10-14.md) |
| native lab Juice Shop/DVWA/WebGoat (2026-10-20, measured; Gash standard/deep + Nuclei) | [native-lab-2026-10-20.md](native-lab-2026-10-20.md) |
| compose lab DVWA/Juice Shop (2026-10-14, BLOCKED: no docker) | [lab-compose-dvwa-juiceshop-2026-10-14.md](lab-compose-dvwa-juiceshop-2026-10-14.md) |
| compose lab DVWA/Juice Shop/WebGoat (2026-10-15, BLOCKED: no docker; native lab supersedes the measured subset) | [lab-compose-2026-10-15.md](lab-compose-2026-10-15.md) |
| Nuclei comparison (fixture lab 2026-10-19; native lab 2026-10-20) | [nuclei-comparison-2026-10-14.md](nuclei-comparison-2026-10-14.md) |
| benchmark, fixtures standard + deep (2026-10-19, measured; three recall fixes) | [benchmark-fixtures-2026-10-19.md](benchmark-fixtures-2026-10-19.md) |

### Tier 1 Expansion Pack (100)

| Plugin | Report |
|---|---|
| alertmanager-version-disclosure | [alertmanager-version-disclosure.md](alertmanager-version-disclosure.md) |
| arangodb-version-disclosure | [arangodb-version-disclosure.md](arangodb-version-disclosure.md) |
| authelia-version-disclosure | [authelia-version-disclosure.md](authelia-version-disclosure.md) |
| authentik-version-disclosure | [authentik-version-disclosure.md](authentik-version-disclosure.md) |
| bitrix-version-disclosure | [bitrix-version-disclosure.md](bitrix-version-disclosure.md) |
| bookstack-version-disclosure | [bookstack-version-disclosure.md](bookstack-version-disclosure.md) |
| bugzilla-version-disclosure | [bugzilla-version-disclosure.md](bugzilla-version-disclosure.md) |
| casdoor-version-disclosure | [casdoor-version-disclosure.md](casdoor-version-disclosure.md) |
| cgit-version-disclosure | [cgit-version-disclosure.md](cgit-version-disclosure.md) |
| cloudbeaver-version-disclosure | [cloudbeaver-version-disclosure.md](cloudbeaver-version-disclosure.md) |
| cloudreve-version-disclosure | [cloudreve-version-disclosure.md](cloudreve-version-disclosure.md) |
| coep-unsafe-none | [coep-unsafe-none.md](coep-unsafe-none.md) |
| concourse-version-disclosure | [concourse-version-disclosure.md](concourse-version-disclosure.md) |
| confluence-version-disclosure | [confluence-version-disclosure.md](confluence-version-disclosure.md) |
| coop-unsafe-none | [coop-unsafe-none.md](coop-unsafe-none.md) |
| craft-cms-version-disclosure | [craft-cms-version-disclosure.md](craft-cms-version-disclosure.md) |
| csp-base-uri-missing | [csp-base-uri-missing.md](csp-base-uri-missing.md) |
| csp-default-src-missing | [csp-default-src-missing.md](csp-default-src-missing.md) |
| csp-form-action-missing | [csp-form-action-missing.md](csp-form-action-missing.md) |
| permissions-policy-payment-missing | [permissions-policy-payment-missing.md](permissions-policy-payment-missing.md) |
| csp-require-trusted-types-missing | [csp-require-trusted-types-missing.md](csp-require-trusted-types-missing.md) |
| csp-upgrade-insecure-requests-missing | [csp-upgrade-insecure-requests-missing.md](csp-upgrade-insecure-requests-missing.md) |
| dokuwiki-version-disclosure | [dokuwiki-version-disclosure.md](dokuwiki-version-disclosure.md) |
| dolibarr-version-disclosure | [dolibarr-version-disclosure.md](dolibarr-version-disclosure.md) |
| druid-version-disclosure | [druid-version-disclosure.md](druid-version-disclosure.md) |
| drupal-version-disclosure | [drupal-version-disclosure.md](drupal-version-disclosure.md) |
| erpnext-version-disclosure | [erpnext-version-disclosure.md](erpnext-version-disclosure.md) |
| espocrm-version-disclosure | [espocrm-version-disclosure.md](espocrm-version-disclosure.md) |
| feature-policy-deprecated | [feature-policy-deprecated.md](feature-policy-deprecated.md) |
| flarum-version-disclosure | [flarum-version-disclosure.md](flarum-version-disclosure.md) |
| flink-ui-version-disclosure | [flink-ui-version-disclosure.md](flink-ui-version-disclosure.md) |
| focalboard-version-disclosure | [focalboard-version-disclosure.md](focalboard-version-disclosure.md) |
| gerrit-version-disclosure | [gerrit-version-disclosure.md](gerrit-version-disclosure.md) |
| gitlab-version-disclosure | [gitlab-version-disclosure.md](gitlab-version-disclosure.md) |
| glpi-version-disclosure | [glpi-version-disclosure.md](glpi-version-disclosure.md) |
| gocd-version-disclosure | [gocd-version-disclosure.md](gocd-version-disclosure.md) |
| hsts-preload-missing | [hsts-preload-missing.md](hsts-preload-missing.md) |
| invision-community-version-disclosure | [invision-community-version-disclosure.md](invision-community-version-disclosure.md) |
| jenkins-version-disclosure | [jenkins-version-disclosure.md](jenkins-version-disclosure.md) |
| jira-version-disclosure | [jira-version-disclosure.md](jira-version-disclosure.md) |
| joomla-version-disclosure | [joomla-version-disclosure.md](joomla-version-disclosure.md) |
| kanboard-version-disclosure | [kanboard-version-disclosure.md](kanboard-version-disclosure.md) |
| kodbox-version-disclosure | [kodbox-version-disclosure.md](kodbox-version-disclosure.md) |
| magento-version-disclosure | [magento-version-disclosure.md](magento-version-disclosure.md) |
| matomo-version-disclosure | [matomo-version-disclosure.md](matomo-version-disclosure.md) |
| mediawiki-version-disclosure | [mediawiki-version-disclosure.md](mediawiki-version-disclosure.md) |
| meilisearch-version-disclosure | [meilisearch-version-disclosure.md](meilisearch-version-disclosure.md) |
| mongo-express-version-disclosure | [mongo-express-version-disclosure.md](mongo-express-version-disclosure.md) |
| mybb-version-disclosure | [mybb-version-disclosure.md](mybb-version-disclosure.md) |
| nats-version-disclosure | [nats-version-disclosure.md](nats-version-disclosure.md) |
| nodebb-version-disclosure | [nodebb-version-disclosure.md](nodebb-version-disclosure.md) |
| odoo-version-disclosure | [odoo-version-disclosure.md](odoo-version-disclosure.md) |
| opencart-version-disclosure | [opencart-version-disclosure.md](opencart-version-disclosure.md) |
| opensearch-version-disclosure | [opensearch-version-disclosure.md](opensearch-version-disclosure.md) |
| opentsdb-version-disclosure | [opentsdb-version-disclosure.md](opentsdb-version-disclosure.md) |
| orientdb-version-disclosure | [orientdb-version-disclosure.md](orientdb-version-disclosure.md) |
| osticket-version-disclosure | [osticket-version-disclosure.md](osticket-version-disclosure.md) |
| permissions-policy-camera-missing | [permissions-policy-camera-missing.md](permissions-policy-camera-missing.md) |
| permissions-policy-geolocation-missing | [permissions-policy-geolocation-missing.md](permissions-policy-geolocation-missing.md) |
| permissions-policy-microphone-missing | [permissions-policy-microphone-missing.md](permissions-policy-microphone-missing.md) |
| phpbb-version-disclosure | [phpbb-version-disclosure.md](phpbb-version-disclosure.md) |
| phpldapadmin-version-disclosure | [phpldapadmin-version-disclosure.md](phpldapadmin-version-disclosure.md) |
| prestashop-version-disclosure | [prestashop-version-disclosure.md](prestashop-version-disclosure.md) |
| pydio-version-disclosure | [pydio-version-disclosure.md](pydio-version-disclosure.md) |
| redis-commander-version-disclosure | [redis-commander-version-disclosure.md](redis-commander-version-disclosure.md) |
| referrer-policy-no-referrer-when-downgrade | [referrer-policy-no-referrer-when-downgrade.md](referrer-policy-no-referrer-when-downgrade.md) |
| referrer-policy-unsafe-url | [referrer-policy-unsafe-url.md](referrer-policy-unsafe-url.md) |
| shopware-version-disclosure | [shopware-version-disclosure.md](shopware-version-disclosure.md) |
| sitecore-version-disclosure | [sitecore-version-disclosure.md](sitecore-version-disclosure.md) |
| spark-ui-version-disclosure | [spark-ui-version-disclosure.md](spark-ui-version-disclosure.md) |
| storm-ui-version-disclosure | [storm-ui-version-disclosure.md](storm-ui-version-disclosure.md) |
| suitecrm-version-disclosure | [suitecrm-version-disclosure.md](suitecrm-version-disclosure.md) |
| thanos-version-disclosure | [thanos-version-disclosure.md](thanos-version-disclosure.md) |
| trac-version-disclosure | [trac-version-disclosure.md](trac-version-disclosure.md) |
| typo3-version-disclosure | [typo3-version-disclosure.md](typo3-version-disclosure.md) |
| umbraco-version-disclosure | [umbraco-version-disclosure.md](umbraco-version-disclosure.md) |
| uptime-kuma-version-disclosure | [uptime-kuma-version-disclosure.md](uptime-kuma-version-disclosure.md) |
| vbulletin-version-disclosure | [vbulletin-version-disclosure.md](vbulletin-version-disclosure.md) |
| vikunja-version-disclosure | [vikunja-version-disclosure.md](vikunja-version-disclosure.md) |
| vtiger-version-disclosure | [vtiger-version-disclosure.md](vtiger-version-disclosure.md) |
| wekan-version-disclosure | [wekan-version-disclosure.md](wekan-version-disclosure.md) |
| wikijs-version-disclosure | [wikijs-version-disclosure.md](wikijs-version-disclosure.md) |
| woocommerce-version-disclosure | [woocommerce-version-disclosure.md](woocommerce-version-disclosure.md) |
| wordpress-version-disclosure | [wordpress-version-disclosure.md](wordpress-version-disclosure.md) |
| x-application-context-disclosure | [x-application-context-disclosure.md](x-application-context-disclosure.md) |
| x-aspnet-version-disclosure | [x-aspnet-version-disclosure.md](x-aspnet-version-disclosure.md) |
| x-aspnetmvc-version-disclosure | [x-aspnetmvc-version-disclosure.md](x-aspnetmvc-version-disclosure.md) |
| x-debug-token-disclosure | [x-debug-token-disclosure.md](x-debug-token-disclosure.md) |
| x-debug-token-link-disclosure | [x-debug-token-link-disclosure.md](x-debug-token-link-disclosure.md) |
| x-download-options-missing | [x-download-options-missing.md](x-download-options-missing.md) |
| x-frame-options-allow-from | [x-frame-options-allow-from.md](x-frame-options-allow-from.md) |
| x-generator-disclosure | [x-generator-disclosure.md](x-generator-disclosure.md) |
| x-permitted-cross-domain-policies-missing | [x-permitted-cross-domain-policies-missing.md](x-permitted-cross-domain-policies-missing.md) |
| x-rack-cache-disclosure | [x-rack-cache-disclosure.md](x-rack-cache-disclosure.md) |
| x-runtime-disclosure | [x-runtime-disclosure.md](x-runtime-disclosure.md) |
| x-varnish-disclosure | [x-varnish-disclosure.md](x-varnish-disclosure.md) |
| x-xss-protection-enabled | [x-xss-protection-enabled.md](x-xss-protection-enabled.md) |
| xenforo-version-disclosure | [xenforo-version-disclosure.md](xenforo-version-disclosure.md) |
| xwiki-version-disclosure | [xwiki-version-disclosure.md](xwiki-version-disclosure.md) |
| zammad-version-disclosure | [zammad-version-disclosure.md](zammad-version-disclosure.md) |

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
