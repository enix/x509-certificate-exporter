# Chart, monitoring and delivery

Audit date: 2026-10-23. Scope: Helm values/schema/templates, bundled monitoring,
Dagger and release workflows. P1 means urgent; P2 means a material defect under
a supported configuration; P3 means a lower-priority or conditional risk.

**Evidence:** all 10 example values files, 25 positive schema fixtures and 42
negative schema fixtures produced the expected results with local Helm v4.2.2
(CI pins v4.3.1). Additional targeted renders exposed the defects below.
“Rendered” confirms generated manifests, not successful deployment. No cluster
changes, server-side admission checks, Prometheus rule evaluation, Grafana
rendering or release publishing were performed for this review.

## H1 — P1 — the proxy's upstream port bypasses RBAC

**Evidence: rendered configuration and source inspection.**
[chart/templates/configmap.yaml:15](../../../chart/templates/configmap.yaml#L15)
and [chart/templates/configmap.yaml:123](../../../chart/templates/configmap.yaml#L123)
bind the exporter to `:9091` in proxy mode. The proxy forwards to
`127.0.0.1:9091`
([chart/templates/deployment.yaml:151](../../../chart/templates/deployment.yaml#L151)),
but this does not restrict the exporter's listener to loopback. The chart
creates no NetworkPolicy.

**Trigger and impact:** `helm template audit chart --set rbacProxy.enabled=true`
renders a plain HTTP exporter listening on all interfaces. A peer with network
access to the Pod IP can reach its upstream port directly and bypass the
proxy's TokenReview/SubjectAccessReview checks. A host-network DaemonSet also
exposes that listener on the node network. Omitting `containerPort` does not
close a listening socket. No live-cluster exploit was attempted.

**Remedy and regression:** bind the upstream to `127.0.0.1:<port>` in both
workload modes. Keep the probe listener reachable by kubelet. Add an E2E
assertion that another Pod cannot scrape the upstream directly while authorized
proxy scraping succeeds. Existing
[test/e2e/rbacproxy_test.go:123](../../../test/e2e/rbacproxy_test.go#L123)
checks the proxy endpoint only.

## H2 — P2 — global extension-directory watching cannot render

**Evidence: reproduced schema rejection and template failure.**
[chart/values.yaml:691](../../../chart/values.yaml#L691) and
[chart/values.schema.json:370](../../../chart/values.schema.json#L370)
require string entries, while
[chart/templates/configmap.yaml:170](../../../chart/templates/configmap.yaml#L170)
and [chart/templates/daemonset.yaml:111](../../../chart/templates/daemonset.yaml#L111)
require objects with `directory` and `extension` fields.

**Trigger and impact:** these values are rejected with `got object, want string`:

```yaml
hostPathsExporter:
  daemonSets:
    nodes: {}
  watchSpecificExtensionDirectories:
    - directory: /etc/pki
      extension: crt
```

Changing the entry to the schema-approved string `/etc/pki` instead fails with
`can't evaluate field directory in type interface {}`. The global setting is
therefore unusable. Per-DaemonSet objects happen to work because their contents
are not constrained by the schema.

**Remedy and regression:** define object items with required directory and
extension fields. Exercise both the global and per-DaemonSet forms. The current
[test/render/all-watch-modes.yaml:40](../../../test/render/all-watch-modes.yaml#L40)
fixture exercises only the latter.

## H3 — P2 — extension filters produce duplicate volume definitions

**Evidence: reproduced successful Helm render containing duplicate names and
mount paths.**
[chart/templates/daemonset.yaml:111](../../../chart/templates/daemonset.yaml#L111)
and [chart/templates/daemonset.yaml:232](../../../chart/templates/daemonset.yaml#L232)
emit one mount/volume per extension filter but identify each solely by the
directory hash.

**Trigger and impact:** set
`hostPathsExporter.daemonSets.nodes.watchSpecificExtensionDirectories` to two
entries for `/etc/pki`, one with `extension: crt`, the other with `extension: pem`.
Helm exits successfully but emits the same volume name
`dir-62bab6a993ce08290d5c3015464159d358f28042` twice and duplicates the mount
path. Kubernetes requires unique volume names and mount paths, so the generated
Pod template is invalid. Combining `watchDirectories: [/etc/pki]` with an
extension filter for that directory reproduces the same defect. Admission was
not exercised against a cluster.

**Remedy and regression:** normalize and deduplicate mount roots across watch
modes, retaining separate scan patterns. Validate rendered volume names and
mount paths for uniqueness; cover multiple suffixes and overlapping modes.

## H4 — P2 — enabling the proxy leaves monitoring on plain HTTP

**Evidence: reproduced render and listener configuration inspection.**
[chart/templates/servicemonitor.yaml:24](../../../chart/templates/servicemonitor.yaml#L24)
adds `bearerTokenFile` in proxy mode, but retains the independent scheme whose
default is `http`
([chart/values.yaml:824](../../../chart/values.yaml#L824)). The proxy serves TLS
([chart/templates/deployment.yaml:156](../../../chart/templates/deployment.yaml#L156)).
[chart/templates/podmonitor.yaml:20](../../../chart/templates/podmonitor.yaml#L20)
contains the same scheme mismatch when that monitor is enabled.

**Trigger and impact:** enabling only `rbacProxy.enabled` renders a
ServiceMonitor with a bearer-token file and `scheme: http` against the TLS
proxy. If accepted and selected by the Operator, this configures an HTTP scrape
with credentials instead of a TLS scrape; the target cannot be scraped
successfully. This is a configuration-level finding, not observed token
exfiltration. Operator validation or policy may reject the monitor first.
Changing only the scheme still requires trust configuration for the generated
self-signed certificate.

**Remedy and regression:** derive HTTPS and an appropriate trust configuration,
or reject incomplete proxy/monitor combinations with an actionable error.
Exercise real Operator-managed scrapes, authentication and certificate trust.
The current proxy E2E explicitly disables ServiceMonitor
([test/e2e/values-rbacproxy.yaml:15](../../../test/e2e/values-rbacproxy.yaml#L15)).

## H5 — P2 — proxy-mode liveness probes restart the wrong container

**Evidence: reproduced workload render.**
[chart/templates/deployment.yaml:113](../../../chart/templates/deployment.yaml#L113)
removes probes from the exporter in proxy mode. The proxy receives probes that
call the exporter's probe listener instead
([chart/templates/deployment.yaml:171](../../../chart/templates/deployment.yaml#L171)).
The DaemonSet repeats this arrangement
([chart/templates/daemonset.yaml:135](../../../chart/templates/daemonset.yaml#L135)).

**Trigger and impact:** if the exporter remains running but stops answering
health requests, the failing liveness probe restarts the healthy proxy rather
than the exporter. Conversely, a stuck proxy can satisfy its probe through a
healthy exporter. Ordinary process exits still trigger container restarts; this
finding concerns unresponsive processes. These restart scenarios were inferred
from the rendered probe ownership, not exercised in a cluster.

**Remedy and regression:** attach exporter health probes to the exporter and
check the proxy independently. Fault each process separately and assert which
container restarts and when the Pod becomes unready.

## H6 — P3 — migration comparisons silently exclude prereleases

**Evidence: reproduced Helm comparison behavior; historical source checked.**
[chart/templates/_helpers.tpl:334](../../../chart/templates/_helpers.tpl#L334)
and [chart/templates/_helpers.tpl:339](../../../chart/templates/_helpers.tpl#L339)
use `<4.0.0` and `<4.1.0`. Helm evaluates both comparisons as false for
`4.0.0-alpha.1` and `4.0.0-rc.1`. In contrast, `<4.1.0` is true for stable
`4.0.0`. The previous-version lookup preserves the prerelease suffix
([chart/templates/_helpers.tpl:302](../../../chart/templates/_helpers.tpl#L302)),
so real prerelease labels reach this branch.

**Trigger and impact:** upgrades from prereleases skip the cleanup policy
stated by the migration table, regardless of how old they are. However,
inspected tags `v4.0.0-alpha.3`, `v4.0.0-alpha.8`, `v4.0.0-rc.1` and
`v4.0.0-rc.4` already have the current DaemonSet selector layout. **No failing
historical upgrade was established.** This is a latent migration-policy defect,
not evidence that every prerelease upgrade currently fails.

**Remedy and regression:** decide which historical layouts need recreation,
then express prerelease-inclusive boundaries where appropriate. Test stable,
alpha, RC and build-metadata versions against actual previous resource layouts;
avoid broadening a destructive cleanup rule without that check.

## H7 — P2 — dashboard exporter counts count error reasons

**Evidence: query and metric-definition inspection.**
The “Exporters” and “Reporting Exporters” panels use
`count(x509_source_errors_total)`
([chart/grafana-dashboards/x509-certificate-exporter.json:486](../../../chart/grafana-dashboards/x509-certificate-exporter.json#L486),
[chart/grafana-dashboards/x509-certificate-exporter.json:1716](../../../chart/grafana-dashboards/x509-certificate-exporter.json#L1716)).
That metric has source and reason labels
([pkg/registry/registry.go:138](../../../pkg/registry/registry.go#L138)); source
initialization creates all 17 static reason series at zero
([pkg/registry/registry.go:481](../../../pkg/registry/registry.go#L481),
[pkg/cert/reason.go:61](../../../pkg/cert/reason.go#L61)).

**Trigger and impact:** one clean, single-source exporter contributes 17 series
and is counted as 17 exporters. Additional sources and reason labels inflate
the count further. The “Exporters with Errors” query likewise counts reason
series instead of distinct exporter targets. This result follows directly from
the aggregation; no Grafana instance was rendered.

**Remedy and regression:** count distinct target identity, including cluster
identity where available, or deliberately aggregate and label the panel as a
source count. Test one clean target, multiple sources and multiple error reasons
against a small controlled metric dataset.

## H8 — P2 — an isolated bad-passphrase event cannot reach the alert hold time

**Evidence: PromQL timing analysis; not evaluated with promtool.**
[chart/templates/prometheusrule.yaml:106](../../../chart/templates/prometheusrule.yaml#L106)
uses `increase(...[15m]) > 0`; the next line requires `for: 15m`.

**Trigger and impact:** a watched keystore fails once after a zero baseline has
been scraped, then remains unchanged and unreadable. Its counter increments
once. The positive increase remains visible for less than 15 minutes after the
first positive evaluation: the zero baseline leaves the range before the hold
can finish. The alert therefore never fires for this single persistent failure.
An initial failure that precedes the first scrape can also lack the baseline
needed to detect an increase.

**Remedy and regression:** use a shorter/no hold for event alerts, a longer
lookback than hold, or a current-error gauge if the intended condition is “still
unreadable.” Add a `promtool test rules` case with a zero baseline, one increment
and a flat counter, evaluated over 30 minutes. Current string-based alert
fixtures cannot verify this behavior.

## Secondary findings

| ID / priority | Evidence and reference | Trigger and impact | Remedy / regression |
| --- | --- | --- | --- |
| H9 / P2 | **Source inspection:** [chart/templates/rbacproxy-tls.secret.yaml:24](../../../chart/templates/rbacproxy-tls.secret.yaml#L24). Generated certificates last 365 days; existing certificate/key data is reused without expiry checks. | A long-lived installation with certificate verification eventually loses scrapes; Helm upgrades preserve the expired certificate. No live rotation was tested. | Define renewal and trust rotation, or require a managed Secret. Test upgrade with an expired serving certificate. |
| H10 / P2 | **Rendered:** [chart/templates/_helpers.tpl:18](../../../chart/templates/_helpers.tpl#L18), [chart/templates/configmap.yaml:15](../../../chart/templates/configmap.yaml#L15). | `rbacProxy.enabled=true` and `upstreamListenPort=8080` produce main and probe listeners on the same `:8080` address. Both cannot bind. Other main/probe/proxy collisions are also accepted. | Validate effective listener uniqueness; add negative fixtures for every mode. |
| H11 / P2 | **Rendered, consequence conditional on Secret content:** [chart/templates/configmap.yaml:16](../../../chart/templates/configmap.yaml#L16), [chart/templates/deployment.yaml:151](../../../chart/templates/deployment.yaml#L151). | Combining `rbacProxy.enabled=true` with an existing web configuration Secret is accepted. If that config enables exporter TLS, the proxy still sends HTTP upstream and scrapes fail. | Reject incompatible modes or implement an explicit supported upstream TLS/auth configuration; test both combinations. |
| H12 / P2 | **Source inspection:** [chart/templates/_helpers.tpl:307](../../../chart/templates/_helpers.tpl#L307), [.github/workflows/release.yaml:308](../../../.github/workflows/release.yaml#L308). | Publishing with a custom `CHART_NAME` changes the chart label prefix, but migration parsing only strips `x509-certificate-exporter-`. A subsequent upgrade feeds an invalid version to `semverCompare`. No cluster upgrade was run. | Parse the actual chart identity or store version separately. Test custom chart names with previous resources. |
| H13 / P2 | **Source inspection:** [.goreleaser.yaml:177](../../../.goreleaser.yaml#L177), [.github/workflows/release.yaml:333](../../../.github/workflows/release.yaml#L333), [chart/values.yaml:38](../../../chart/values.yaml#L38). | A nondefault `IMAGE_NAME` changes published image repositories, but packaging changes only chart name/version/appVersion. The chart keeps the default image repository and can deploy the wrong image or fail to pull. | Propagate the release image identity into chart values; validate distinct image/chart names before publishing. No registry writes were performed. |

## Delivery and verification risks

| ID / priority | Evidence, consequence and action |
| --- | --- |
| D1 / P2 — CI gates differ from local checks | **Workflow inspection:** [.github/workflows/test.yaml:26](../../../.github/workflows/test.yaml#L26) contains no Helm render or fuzz job, although [Taskfile.yml:213](../../../Taskfile.yml#L213) runs both. Render-only fixture changes do not trigger the relevant jobs. Release also explicitly skips E2E at [.github/workflows/release.yaml:108](../../../.github/workflows/release.yaml#L108). Align gates with the intended contract and require a documented substitute for omitted deployment tests. See [test coverage](03-test-coverage.md). |
| D2 / P2 — successful lint does not establish runtime compatibility | **Test implementation inspection:** [dagger/test.go:33](../../../dagger/test.go#L33), [dagger/render_alignment.go:44](../../../dagger/render_alignment.go#L44). The Helm checks do not validate Kubernetes/Operator admission, generated exporter-config semantics, upgrade behavior or PromQL timing; clean-install E2E covers only a subset of combinations. Add focused checks for H1–H8, separate checks for the Dagger module and accessible coverage artifacts. See [test coverage](03-test-coverage.md) and [architecture](04-architecture.md). |
| D3 / P2 — generated schema/documentation can drift outside the trigger paths | **Workflow inspection:** [.github/workflows/chart-readme.yaml:18](../../../.github/workflows/chart-readme.yaml#L18) triggers only for values and README-template inputs. Output-only changes or generator changes can bypass verification; the release workflow does not invoke this reusable verifier. Include generated outputs and generator dependencies in trigger paths and verify before release. See [test coverage](03-test-coverage.md). |
| D4 / P2 — the stated SLSA Level 3 assurance is not established | **Workflow and official-guidance inspection:** [.github/workflows/release.yaml:111](../../../.github/workflows/release.yaml#L111) builds and attests within one ordinary job; [.github/workflows/release.yaml:204](../../../.github/workflows/release.yaml#L204) adds artifact provenance. The current structure does not establish the extra isolated-builder guarantee behind the public Level 3 claim. Correct the assurance claim or implement and verify the necessary isolation. See [architecture](04-architecture.md) and [documentation cleanup](05-documentation-cleanup.md). |

For D4, GitHub documents artifact attestations alone as SLSA Build Level 2 and
explains the additional reusable-build-workflow isolation for Level 3:
[artifact-attestation assurance levels](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
and [Level 3 configuration and verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating)
(consulted 2026-10-23). This is an assurance-level finding, not a claim that
existing signatures are invalid. Actual repository protections, Environment
reviewers and published artifact validity were not inspected.
