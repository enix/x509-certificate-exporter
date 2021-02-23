# 🔏 X.509 Certificates Exporter

[![Build status](https://gitlab.com/enix.io/x509-certificate-exporter/badges/master/pipeline.svg)](https://gitlab.com/enix.io/x509-certificate-exporter/-/pipelines)
[![Code coverage](https://gitlab.com/enix.io/x509-certificate-exporter/badges/master/coverage.svg)](https://gitlab.com/enix.io/x509-certificate-exporter/-/pipelines)
[![Go Report](https://goreportcard.com/badge/github.com/enix/x509-certificate-exporter)](https://goreportcard.com/report/github.com/enix/x509-certificate-exporter)

A Prometheus exporter for certificates focusing on expiration monitoring, written in Go with cloud deployments in mind.

Get notified before they expire:
* PEM encoded files, by path or scanning directories
* Kubeconfigs with embedded certificates or file references
* TLS Secrets from a Kubernetes cluster

The following metrics are available:
* `x509_cert_not_before`
* `x509_cert_not_after`
* `x509_cert_expired`
* `x509_read_errors`

Best when installed with the [Helm Chart](https://github.com/enix/helm-charts/tree/master/charts/x509-certificate-exporter) and using the [Grafana Dashboard](https://grafana.com/grafana/dashboards/13922) ID `13922`:

![Grafana Dashboard](./docs/grafana-dashboard.jpg)

## Installation

### Kubernetes

We recommend you check out our [x509-certificate-exporter Helm Chart](https://github.com/enix/helm-charts/tree/master/charts/x509-certificate-exporter)
to easily deploy monitoring of Kubernetes Secrets and/or Nodes certificates - control plane, workers. Most use cases
should be covered with Deployment and DaemonSet options. ServiceMonitor and PrometheusRule resources are available for
prometheus-operator users.

### Docker image

A docker image is available at [enix/x509-certificate-exporter](https://hub.docker.com/r/enix/x509-certificate-exporter).

### From source

You can build the executable by using:

```
go build ./cmd/x509-certificate-exporter
```

## Usage

```
Usage: x509-certificate-exporter [-h] [--debug] [-d value] [--exclude-label value] [--exclude-namespace value] [-f value] [--include-label value] [--include-namespace value] [-k value] [-p value] [--trim-path-components value] [--watch-kube-secrets] [parameters ...]
     --debug       enable debug mode
 -d, --watch-dir=value
                   watch one or more directory which contains x509 certificate
                   files (not recursive)
     --exclude-label=value
                   removes the kube secrets with the given label (or label
                   value if specified) from the watch list (applied after
                   --include-label)
     --exclude-namespace=value
                   removes the given kube namespace from the watch list
                   (applied after --include-namespace)
 -f, --watch-file=value
                   watch one or more x509 certificate file
 -h, --help        show this help message and exit
     --include-label=value
                   add the kube secrets with the given label (or label value if
                   specified) to the watch list (when used, all secrets are
                   excluded by default)
     --include-namespace=value
                   add the given kube namespace to the watch list (when used,
                   all namespaces are excluded by default)
 -k, --watch-kubeconf=value
                   watch one or more Kubernetes client configuration (kind
                   Config) which contains embedded x509 certificates or PEM
                   file paths
 -p, --port=value  prometheus exporter listening port [9090]
     --trim-path-components=value
                   remove <n> leading component(s) from path in label(s)
     --watch-kube-secrets
                   scrape kubernetes.io/tls secrets and monitor them
```

## FAQ

### Why are you using the `not after` timestamp rather than a remaining number of seconds?

For two reasons.

First, Prometheus tends to do better storage consumption when a value stays identical over checks.

Then, it is better to compute the remaining time through a prometheus query as some latency (seconds) can exist
between this exporter check and your alert or query being run.

Here is an exemple:

```
x509_cert_not_after - time()
```

### How to ensure it keeps working over time?

Changes in paths or deleted files may silently break the ability to watch critical certificates.

Because it's never convenient to alert on disapearing metrics, the exporter will publish on `x509_read_errors` how many
paths could not be read. It will also count Kubernetes API responses failures, but won't count deleted secrets.

A basic alert would be:
```
x509_read_errors > 0
```
