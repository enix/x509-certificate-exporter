# -*- mode: Python -*-
# Dev loop (driven from Taskfile.yml):
#   task dev:up     — `dev:cluster:up` then `tilt up`. Tilt always sees a
#                     healthy cluster + populated kubeconfig at startup.
#   task dev:down   — tilt down (cluster persists)
#   task dev:cluster:down — destroy cluster + registry + local kubeconfig
#
# Cluster bootstrap is intentionally NOT a Tilt resource: Tilt caches its
# kubeconfig at startup and does not reload it, so a Tilt-managed bootstrap
# would be either a no-op (cluster pre-existed) or useless (Tilt cannot use
# a cluster that came up after it).
#
# Pipeline:
#   1. goreleaser release --snapshot (tilt mode) → builds busybox image, loads
#                                                  into local Docker daemon
#   2. tilt push                                  → Tilt tags and pushes to 127.0.0.1:5000
#   3. helm install                               → deploys exporter, image pulled from local registry
#   4. seed                                       → populates Secrets across namespaces

# Constants below must match the dev vars in Taskfile.yml (DEV_CLUSTER,
# DEV_REGISTRY, DEV_REGISTRY_PORT). If they drift, `tilt up` will silently
# build/push to the wrong registry or refuse to deploy.
CLUSTER_NAME = "x509ce-dev"
REGISTRY_NAME = "x509ce-dev-registry"
REGISTRY_HOST_PORT = 5000

# Refuse to deploy anywhere other than the dedicated dev k3d cluster — guards
# against a stray KUBECONFIG pointing at another local cluster.
allow_k8s_contexts("k3d-" + CLUSTER_NAME)
default_registry(
    "127.0.0.1:%d" % REGISTRY_HOST_PORT,
    host_from_cluster="k3d-%s:%d" % (REGISTRY_NAME, REGISTRY_HOST_PORT),
)

IMAGE = "x509-certificate-exporter"

# Renovate-tracked (custom regex manager in renovate.json5).
KUBE_PROMETHEUS_VERSION = "84.4.0"

# 1. Build via GoReleaser ------------------------------------------------------
# custom_build hands the build off to GoReleaser in "tilt mode"
# (GORELEASER_TILT=1), which gates a dedicated dockers_v2 entry that:
#   - uses the same Dockerfile.busybox as the release pipeline (single
#     source of truth for the dev image == release image),
#   - builds only the host arch + only the busybox variant,
#   - tags directly with what Tilt expects via TILT_IMAGE_REPO/TAG.
#
# GoReleaser's dockers_v2 appends a `-<arch>` suffix to local tags in
# snapshot mode (anti-collision when buildx loads multi-platform
# images into Docker). The `docker tag` re-aliases to the bare
# EXPECTED_REF Tilt expects (skips_local_docker=False).
custom_build(
    ref=IMAGE,
    command=" && ".join([
        'export TILT_IMAGE_REPO="${EXPECTED_REF%:*}"',
        'export TILT_IMAGE_TAG="${EXPECTED_REF##*:}"',
        'export GORELEASER_TILT=1',
        'export IMAGE_NAME=x509-certificate-exporter',
        'goreleaser release --snapshot --skip=publish,sign,sbom,archive,before --clean',
        'docker tag "${EXPECTED_REF}-$(go env GOARCH)" "$EXPECTED_REF"',
    ]),
    deps=[
        "./cmd",
        "./pkg",
        "./internal",
        "./go.mod",
        "./go.sum",
        "./build/Dockerfile.busybox",
        "./.goreleaser.yaml",
    ],
    skips_local_docker=False,
)

# 2. Deploy via Helm chart -----------------------------------------------------
load("ext://helm_resource", "helm_resource", "helm_repo")

# Prometheus Operator + minimal Prometheus instance. The bundled chart
# (kube-prometheus-stack) brings the CRDs that the x509-certificate-exporter
# chart needs (ServiceMonitor, PrometheusRule). All optional sub-charts are
# disabled to keep the cluster lightweight; Prometheus selects every
# ServiceMonitor/PrometheusRule in the cluster (no label filter) so dev work
# does not require labeling the exporter's resources.
helm_repo(
    name="prometheus-community",
    url="https://prometheus-community.github.io/helm-charts",
    labels=["infra"],
)

helm_resource(
    name="kube-prometheus",
    chart="prometheus-community/kube-prometheus-stack",
    namespace="monitoring",
    flags=[
        "--create-namespace",
        "--version", KUBE_PROMETHEUS_VERSION,
        "--set", "alertmanager.enabled=false",
        "--set", "grafana.enabled=false",
        "--set", "kubeStateMetrics.enabled=false",
        "--set", "nodeExporter.enabled=false",
        "--set", "kubeApiServer.enabled=false",
        "--set", "kubelet.enabled=false",
        "--set", "kubeControllerManager.enabled=false",
        "--set", "coreDns.enabled=false",
        "--set", "kubeDns.enabled=false",
        "--set", "kubeEtcd.enabled=false",
        "--set", "kubeScheduler.enabled=false",
        "--set", "kubeProxy.enabled=false",
        "--set", "defaultRules.create=false",
        # Admission webhooks + operator TLS disabled in dev: enabling them
        # requires a cert source (cert-manager or a webhook helper), which is
        # overkill for a local loop. Re-enable if you ever need to validate
        # PrometheusRule/ServiceMonitor admission against the operator's
        # webhook in dev — otherwise misconfigured CRs only surface at apply
        # time, not at edit time.
        "--set", "prometheusOperator.admissionWebhooks.enabled=false",
        "--set", "prometheusOperator.tls.enabled=false",
        # Pick up ServiceMonitors / PrometheusRules from any namespace, no label filter
        "--set", "prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false",
        "--set", "prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false",
        "--set", "prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false",
        "--set", "prometheus.prometheusSpec.probeSelectorNilUsesHelmValues=false",
        # Trim retention so the dev pod stays small
        "--set", "prometheus.prometheusSpec.retention=2h",
        "--set", "prometheus.prometheusSpec.replicas=1",
    ],
    resource_deps=["prometheus-community"],
    labels=["infra"],
)

# Dedicated port-forward for the Prometheus UI: serve_cmd keeps the forward up
# as long as Tilt runs, and the link shows up in the Tilt dashboard.
local_resource(
    "prometheus-ui",
    serve_cmd=" && ".join(
        [
            "kubectl --namespace monitoring wait --for=condition=Ready pod "
            + "-l app.kubernetes.io/name=prometheus --timeout=180s",
            "kubectl --namespace monitoring port-forward "
            + "svc/kube-prometheus-kube-prome-prometheus 9090:9090",
        ]
    ),
    resource_deps=["kube-prometheus"],
    links=["http://127.0.0.1:9090"],
    labels=["infra"],
)


helm_resource(
    name="x509-certificate-exporter",
    chart="./chart",
    namespace="monitoring",
    flags=[
        "--create-namespace",
        "--values", "./dev/values.yaml",
    ],
    image_deps=[IMAGE],
    image_keys=[("image.registry", "image.repository", "image.tag")],
    resource_deps=["kube-prometheus"],
    labels=["app"],
    port_forwards=["9793:9793"],
)

# 3. Seed test data ------------------------------------------------------------
local_resource(
    "seed",
    cmd="go run ./dev/seed",
    deps=["./dev/seed", "./dev/scenarios"],
    resource_deps=["x509-certificate-exporter"],
    labels=["app"],
)
