// Package cert defines the neutral data model used by the
// x509-certificate-exporter and exposed for library use.
//
// The package contains no IO and no business logic. It defines:
//
//   - the data types Bundle, Item, SourceRef and ItemError that flow
//     between sources, parsers and the metric registry;
//   - the FormatParser interface implemented by package cert/pem and
//     cert/pkcs12;
//   - the Source interface that any provider of certificates must
//     implement (file scanner, Kubernetes informer, custom backend);
//   - the Sink interface that the registry implements to receive bundles.
//
// # Embedded use case
//
// To embed certificate monitoring inside another Go binary (operator,
// controller, sidecar) without running this exporter as a separate
// process:
//
//  1. Create a *registry.Registry and register it with your own
//     prometheus.Registry.
//  2. Implement cert.Source for your data backend (or reuse one of the
//     in-tree implementations) and call its Run method, passing the
//     *registry.Registry as Sink.
//  3. Serve /metrics from your own HTTP handler using promhttp.HandlerFor.
//
// The registry takes care of label collisions, error counting, and the
// optional discriminator label as described in the rewrite spec.
package cert
