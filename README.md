# x509 Exporter

A prometheus exporter which presents certificate file metrics enabling certificate expiration monitoring.

The following metrics are available:
* x509_cert_not_before
* x509_cert_not_after
* x509_cert_expired

## Installation

### Docker image

A docker image is available at [enix/x509-exporter](https://hub.docker.com/r/enix/x509-exporter)

### From source

You can build the executable by using :

```
go build ./cmd/x509-exporter
```

## Usage

```
Usage: x509-exporter [-h] [--debug] [-d value] [-f value] [-k value] [-p value] [--trim-path value] [parameters ...]
     --debug       enable debug mode
 -d, --watch-dir=value
                   watch one or more directory which contains x509 certificate
                   files
 -f, --watch-file=value
                   watch one or more x509 certificate file
 -h, --help        show this help message and exit
 -k, --watch-kubeconf=value
                   watch one or more Kubernetes client configuration (kind
                   Config) which contains embedded x509 certificates or PEM
                   file paths
 -p, --port=value  prometheus exporter listening port [9090]
     --trim-path=value
                   remove leading elements from path(s) in label(s)
```

## FAQ

### Can I use it in my Kubernetes cluster ?

This exporter has been built with a kubernetes usage in mind, so it should be pretty straighforward to setup.

### Why are you using the `not after` timestamp rather than a remaining number of seconds ?

For two reasons.

First, prometheus tends to do better storage consumption when a value stays identical over checks.

Then, it is better to compute the remaining time through a prometheus query as some latency (seconds) can exist between this exporter check and your alert or query being run.

Here is an exemple:

```
x509_cert_not_after - time()
```
