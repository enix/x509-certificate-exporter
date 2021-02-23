# 🔏 X.509 Certificates Exporter

[![Build status](https://gitlab.com/enix.io/x509-certificate-exporter/badges/master/pipeline.svg)](https://gitlab.com/enix.io/x509-certificate-exporter/-/pipelines)
[![Code coverage](https://gitlab.com/enix.io/x509-certificate-exporter/badges/master/coverage.svg)](https://gitlab.com/enix.io/x509-certificate-exporter/-/pipelines)
[![Go Report](https://goreportcard.com/badge/github.com/enix/x509-certificate-exporter)](https://goreportcard.com/report/github.com/enix/x509-certificate-exporter)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Brought by Enix](https://img.shields.io/badge/Brought%20to%20you%20by-ENIX-%23377dff?labelColor=888&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBAkQIg/iouK/AAABZ0lEQVQY0yXBPU8TYQDA8f/zcu1RSDltKliD0BKNECYZmpjgIAOLiYtubn4EJxI/AImzg3E1+AGcYDIMJA7lxQQQQRAiSSFG2l457+655x4Gfz8B45zwipWJ8rPCQ0g3+p9Pj+AlHxHjnLHAbvPW2+GmLoBN+9/+vNlfGeU2Auokd8Y+VeYk/zk6O2fP9fcO8hGpN/TUbxpiUhJiEorTgy+6hUlU5N1flK+9oIJHiKNCkb5wMyOFw3V9o+zN69o0Exg6ePh4/GKr6s0H72Tc67YsdXbZ5gENNjmigaXbMj0tzEWrZNtqigva5NxjhFP6Wfw1N1pjqpFaZQ7FAY6An6zxTzHs0BGqY/NQSnxSBD6WkDRTf3O0wG2Ztl/7jaQEnGNxZMdy2yET/B2xfGlDagQE1OgRRvL93UOHqhLnesPKqJ4NxLLn2unJgVka/HBpbiIARlHFq1n/cWlMZMne1ZfyD5M/Aa4BiyGSwP4Jl3UAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjAtMDQtMDlUMTQ6MzQ6MTUrMDI6MDDBq8/nAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIwLTA0LTA5VDE0OjM0OjE1KzAyOjAwsPZ3WwAAAABJRU5ErkJggg==)](https://enix.io)

A Prometheus exporter for certificates focusing on expiration monitoring, written in Go with cloud deployments in mind.

Get notified before they expire:
* PEM encoded files, by path or scanning directories
* Kubeconfigs with embedded certificates or file references
* TLS Secrets from a Kubernetes cluster

![Grafana Dashboard](./docs/grafana-dashboard.jpg)

## Installation

### 🏃 TL;DR

The [Helm chart](https://github.com/enix/helm-charts/tree/master/charts/x509-certificate-exporter#-tldr) is the most straightforward way to get a fully-featured exporter running on your cluster.
The chart is also highly-customizable if you wish to. See the [chart documentation](https://github.com/enix/helm-charts/tree/master/charts/x509-certificate-exporter) to learn more.

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
* `x509_cert_not_before`
* `x509_cert_not_after`
* `x509_cert_expired`
* `x509_read_errors`

### Advanced usage

For advanced configuration, see the program's `--help` :

```
Usage: x509-certificate-exporter [-hv] [--debug] [-d value] [--exclude-label value] [--exclude-namespace value] [-f value] [--include-label value] [--include-namespace value] [-k value] [-p value] [--trim-path-components value] [--watch-kube-secrets] [parameters ...]
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
                   remove <n> leading component(s) from path(s) in label(s)
 -v, --version     show version info and exit
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
