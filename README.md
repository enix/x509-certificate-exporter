# 🔏 X.509 Certificate Exporter

[![Build status](https://gitlab.com/enix.io/x509-certificate-exporter/badges/master/pipeline.svg)](https://gitlab.com/enix.io/x509-certificate-exporter/-/pipelines)
[![Code coverage](https://gitlab.com/enix.io/x509-certificate-exporter/badges/master/coverage.svg)](https://gitlab.com/enix.io/x509-certificate-exporter/-/pipelines)
[![Go Report](https://goreportcard.com/badge/github.com/enix/x509-certificate-exporter)](https://goreportcard.com/report/github.com/enix/x509-certificate-exporter)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Brought by Enix](https://img.shields.io/badge/Brought%20to%20you%20by-ENIX-%23377dff?labelColor=888&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBAkQIg/iouK/AAABZ0lEQVQY0yXBPU8TYQDA8f/zcu1RSDltKliD0BKNECYZmpjgIAOLiYtubn4EJxI/AImzg3E1+AGcYDIMJA7lxQQQQRAiSSFG2l457+655x4Gfz8B45zwipWJ8rPCQ0g3+p9Pj+AlHxHjnLHAbvPW2+GmLoBN+9/+vNlfGeU2Auokd8Y+VeYk/zk6O2fP9fcO8hGpN/TUbxpiUhJiEorTgy+6hUlU5N1flK+9oIJHiKNCkb5wMyOFw3V9o+zN69o0Exg6ePh4/GKr6s0H72Tc67YsdXbZ5gENNjmigaXbMj0tzEWrZNtqigva5NxjhFP6Wfw1N1pjqpFaZQ7FAY6An6zxTzHs0BGqY/NQSnxSBD6WkDRTf3O0wG2Ztl/7jaQEnGNxZMdy2yET/B2xfGlDagQE1OgRRvL93UOHqhLnesPKqJ4NxLLn2unJgVka/HBpbiIARlHFq1n/cWlMZMne1ZfyD5M/Aa4BiyGSwP4Jl3UAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjAtMDQtMDlUMTQ6MzQ6MTUrMDI6MDDBq8/nAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIwLTA0LTA5VDE0OjM0OjE1KzAyOjAwsPZ3WwAAAABJRU5ErkJggg==)](https://enix.io)

A Prometheus exporter for certificates focusing on expiration monitoring, written in Go. Designed to monitor Kubernetes clusters from inside, it can also be used as a standalone exporter.

Get notified before they expire:

- PEM encoded files, by path or scanning directories
- Kubeconfigs with embedded certificates or file references
- TLS Secrets from a Kubernetes cluster

![Grafana Dashboard](./docs/grafana-dashboard.jpg)

## Installation

### 🏃 TL; DR

The [Helm chart](https://github.com/enix/x509-certificate-exporter/tree/master/deploy/charts/x509-certificate-exporter#-tldr) is the most straightforward way to get a fully-featured exporter running on your cluster.
The chart is also highly-customizable if you wish to. See the [chart documentation](https://github.com/enix/x509-certificate-exporter/tree/master/deploy/charts/x509-certificate-exporter) to learn more.

The provided [Grafana Dashboard](https://grafana.com/grafana/dashboards/13922) can also be used to display the exporter's metrics on your Grafana instance.

### Using Docker

A docker image is available at [enix/x509-certificate-exporter](https://hub.docker.com/r/enix/x509-certificate-exporter).

### Using the pre-built binaries

Every [release](https://github.com/enix/x509-certificate-exporter/releases) comes with pre-built binaries for many supported platforms.

### Using the source

The project's entry point is `./cmd/x509-certificate-exporter`.
You can run & build it as any other Go program :

```bash
go build ./cmd/x509-certificate-exporter
```

## Usage

The following metrics are available:

- `x509_cert_not_before`
- `x509_cert_not_after`
- `x509_cert_expired`
- `x509_read_errors`

### Prometheus Alerts

When installation is not performed with Helm, the following Prometheus alerting
rules may be deployed manually:

```
rules:
    - alert: X509ExporterReadErrors
        annotations:
            description: Over the last 15 minutes, this x509-certificate-exporter instance
                has experienced errors reading certificate files or querying the Kubernetes
                API. This could be caused by a misconfiguration if triggered when the exporter
                starts.
            summary: Increasing read errors for x509-certificate-exporter
        expr: delta(x509_read_errors[15m]) > 0
        for: 5m
        labels:
            severity: warning
    - alert: CertificateRenewal
        annotations:
            description: Certificate for "{{ $labels.subject_CN }}" should be renewed
                {{if $labels.secret_name }}in Kubernets secret "{{ $labels.secret_namespace
                }}/{{ $labels.secret_name }}"{{else}}at location "{{ $labels.filepath }}"{{end}}
            summary: Certificate should be renewed
        expr: ((x509_cert_not_after - time()) / 86400) < 28
        for: 15m
        labels:
            severity: warning
    - alert: CertificateExpiration
        annotations:
            description: Certificate for "{{ $labels.subject_CN }}" is about to expire
                {{if $labels.secret_name }}in Kubernets secret "{{ $labels.secret_namespace
                }}/{{ $labels.secret_name }}"{{else}}at location "{{ $labels.filepath }}"{{end}}
            summary: Certificate is about to expire
        expr: ((x509_cert_not_after - time()) / 86400) < 14
        for: 15m
        labels:
            severity: critical
```

### Advanced usage

For advanced configuration, see the program's `--help` :

```
Usage: x509-certificate-exporter [-hv] [-b value] [--debug] [-d value] [--exclude-label value] [--exclude-namespace value] [--expose-per-cert-error-metrics] [--expose-relative-metrics] [-f value] [--include-label value] [--include-namespace value] [-k value] [-l value] [--max-cache-duration value] [-s value] [--trim-path-components value] [--watch-kube-secrets] [parameters ...]
 -b, --listen-address=value
                address on which to bind and expose metrics [:9793]
     --debug    enable debug mode
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
     --expose-per-cert-error-metrics
                expose additionnal error metric for each certificate
                indicating wether it has failure(s)
     --expose-relative-metrics
                expose additionnal metrics with relative durations instead
                of absolute timestamps
 -f, --watch-file=value
                watch one or more x509 certificate file
 -h, --help     show this help message and exit
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
 -l, --expose-labels=value
     --max-cache-duration=value
                maximum cache duration for kube secrets. cache is per
                namespace and randomized to avoid massive requests.
 -s, --secret-type=value
                one or more kubernetes secret type & key to watch (e.g.
                "kubernetes.io/tls:tls.crt"
     --trim-path-components=value
                remove <n> leading component(s) from path(s) in label(s)
 -v, --version  show version info and exit
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

When collecting metrics from tools like Datadog that does not have timestamp functions,
the exporter can be run with the `--expose-relative-metrics` flag in order to add the following optional metrics:

- `x509_cert_valid_since_seconds`
- `x509_cert_expires_in_seconds`

### How to ensure it keeps working over time?

Changes in paths or deleted files may silently break the ability to watch critical certificates.

Because it's never convenient to alert on disapearing metrics, the exporter will publish on `x509_read_errors` how many
paths could not be read. It will also count Kubernetes API responses failures, but won't count deleted secrets.

A basic alert would be:

```
x509_read_errors > 0
```
