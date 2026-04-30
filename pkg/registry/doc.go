// Package registry stores the in-memory snapshot of all discovered
// certificate bundles and exposes them as Prometheus metrics.
//
// The Registry type implements both cert.Sink (the entry point for
// sources) and prometheus.Collector (the entry point for scrapes). It is
// the single place where label sets, metric names, and collision
// handling are defined.
//
// Library use
//
// A Registry is safe to register with a third-party prometheus.Registry,
// independent of the exporter binary itself:
//
//	reg := registry.New(registry.Config{ ExposeRelative: true }, logger)
//	prom := prometheus.NewRegistry()
//	prom.MustRegister(reg)
//
//	mySource.Run(ctx, reg) // mySource implements cert.Source
//
//	http.Handle("/metrics", promhttp.HandlerFor(prom, promhttp.HandlerOpts{}))
//
// Collision handling
//
// When two bundle items would map to the same metric series (same name +
// labels), the registry resolves the conflict according to Config.Collision:
// CollisionAuto adds a discriminator label only on the colliding rows,
// CollisionAlways always adds the label, and CollisionNever deduplicates
// by keeping the row with the smallest NotAfter and increments
// x509_cert_collision_total.
package registry
