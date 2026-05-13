// Package cert defines the neutral data model used across the exporter.
//
// All certificate sources produce Bundles, all format parsers consume bytes
// and produce Bundles. The registry consumes Bundles. No layer below this
// package knows anything about the specifics of files, Kubernetes Secrets,
// PEM, or PKCS#12.
package cert

import (
	"context"
	"crypto/x509"
)

// Canonical values for SourceRef.Kind. These strings appear verbatim in
// exposed Prometheus labels (`source_kind`), so they are part of the
// public contract — do not change the literal values.
const (
	KindFile          = "file"           // local filesystem entry (single file or glob match)
	KindKubeconfig    = "kubeconfig"     // certs embedded in a kubeconfig file
	KindKubeSecret    = "kube-secret"    // Kubernetes Secret resource
	KindKubeConfigMap = "kube-configmap" // Kubernetes ConfigMap resource
	KindKubeCABundle  = "kube-cabundle"  // inline caBundle field of an admission/aggregation resource
)

// Canonical attribute key prefixes used in SourceRef.Attributes for
// per-object Kubernetes labels exposed as Prometheus labels. Both the
// writer (the Kubernetes source) and the reader (the metric registry)
// must use the same prefix; centralising them here prevents silent
// drift that would cause exposeLabels series to disappear.
const (
	AttrSecretLabelPrefix    = "secret_label/"
	AttrConfigMapLabelPrefix = "configmap_label/"
	AttrCABundleLabelPrefix  = "cabundle_label/"
)

// Canonical values for SourceRef.Format and FormatParser.Format(). Used
// as a discriminator at YAML-config validation, parser dispatch, and
// the Prometheus `format` label on diagnostic histograms.
const (
	FormatPEM    = "pem"
	FormatPKCS12 = "pkcs12"
)

// SourceRef identifies where a Bundle was found. It is the unit of identity
// for upsert/delete operations on the registry: a Bundle keyed by its
// SourceRef replaces any previous Bundle with the same ref.
type SourceRef struct {
	Kind       string            // one of the Kind* constants above
	Location   string            // file path, "namespace/name" for k8s, kubeconfig path
	Key        string            // sub-key within Location (Secret data key, JSONPath in kubeconfig); empty for plain file
	Format     string            // "pem" | "pkcs12"
	SourceName string            // logical config-level name (sources[].name)
	Attributes map[string]string // free-form per-kind attributes (k8s labels, etc.)
}

// String produces a stable identifier suitable for logs and as a map key.
func (r SourceRef) String() string {
	if r.Key == "" {
		return r.Kind + ":" + r.Location
	}
	return r.Kind + ":" + r.Location + "#" + r.Key
}

// Role classifies an Item inside a multi-item Bundle. Useful for chains.
type Role string

const (
	RoleUnknown      Role = "unknown"
	RoleLeaf         Role = "leaf"
	RoleIntermediate Role = "intermediate"
	RoleCA           Role = "ca"
)

// Item is one parsed certificate within a Bundle.
type Item struct {
	Index int               // position within the Bundle, 0-based
	Cert  *x509.Certificate // never nil for a successfully parsed Item
	Role  Role
}

// ItemError captures a partial failure in a Bundle. Index == -1 means the
// failure applies to the whole Bundle (e.g., bad_pkcs12, no_certificate_found).
type ItemError struct {
	Index  int
	Reason string // canonical reason code; see reason package
	Err    error
}

// Bundle is the unit of work flowing from sources to the registry.
type Bundle struct {
	Source SourceRef
	Items  []Item
	Errors []ItemError
}

// HasFatalError returns true if the bundle has a Bundle-level error
// (Index == -1) preventing any meaningful Items from being present.
func (b Bundle) HasFatalError() bool {
	for _, e := range b.Errors {
		if e.Index == -1 {
			return true
		}
	}
	return false
}

// FormatParser parses raw bytes into a Bundle. Implementations must be
// stateless and safe for concurrent use.
type FormatParser interface {
	// Format returns the canonical name ("pem", "pkcs12").
	Format() string
	// Parse always returns a Bundle. A parsing failure is reported as an
	// ItemError, never as a non-nil error from this function — error returns
	// are reserved for programmer mistakes (nil opts, etc.).
	Parse(data []byte, ref SourceRef, opts ParseOptions) Bundle
}

// ParseOptions carries per-call hints. Most parsers ignore most fields.
type ParseOptions struct {
	// Pkcs12Passphrase is the passphrase to use for PKCS#12 decoding.
	// Empty string is a valid passphrase for unencrypted bundles.
	Pkcs12Passphrase string
	// Pkcs12TryEmpty, if true and Pkcs12Passphrase fails, retries with "".
	Pkcs12TryEmpty bool
}

// Sink receives Bundles from Sources and forwards them to the registry.
// Implementations must be safe for concurrent use.
type Sink interface {
	Upsert(b Bundle)
	Delete(ref SourceRef)
}

// Source produces Bundles. Run blocks until the context is cancelled.
type Source interface {
	Name() string
	Run(ctx context.Context, sink Sink) error
}
