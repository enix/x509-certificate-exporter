package registry

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/hex"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// LabelOptions are the runtime options used to build labels.
type LabelOptions struct {
	SubjectFields      []string
	IssuerFields       []string
	TrimPathComponents int
}

// fieldsAll is the canonical order of subject/issuer fields used in labels.
var fieldsAll = []string{"C", "ST", "L", "O", "OU", "CN"}

// dnFields returns the subset of fieldsAll requested. Empty in -> all.
func dnFields(in []string) []string {
	if len(in) == 0 {
		return fieldsAll
	}
	want := map[string]struct{}{}
	for _, s := range in {
		want[strings.ToUpper(strings.TrimSpace(s))] = struct{}{}
	}
	out := make([]string, 0, len(want))
	for _, f := range fieldsAll {
		if _, ok := want[f]; ok {
			out = append(out, f)
		}
	}
	return out
}

func dnValue(n pkix.Name, field string) string {
	switch field {
	case "C":
		return first(n.Country)
	case "ST":
		return first(n.Province)
	case "L":
		return first(n.Locality)
	case "O":
		return first(n.Organization)
	case "OU":
		return first(n.OrganizationalUnit)
	case "CN":
		return n.CommonName
	}
	return ""
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func trimPath(p string, n int) string {
	if n <= 0 {
		return p
	}
	abs := strings.HasPrefix(p, "/")
	parts := strings.Split(strings.TrimLeft(p, "/"), "/")
	if n >= len(parts) {
		return ""
	}
	res := strings.Join(parts[n:], "/")
	if abs {
		res = "/" + res
	}
	return res
}

func sanitiseLabel(s string) string {
	if s == "" {
		return "_"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "_"
	}
	if out[0] >= '0' && out[0] <= '9' {
		return "_" + out
	}
	return out
}

// fingerprint computes the discriminator label value: a short hex prefix
// of SHA-256(cert.Raw || sourceRef || index). Including the source ref and
// item index in the hash input guarantees that two byte-identical certs
// from the same bundle (a degenerate but real case — e.g., a CA appearing
// twice in a chain) still get distinct discriminator values.
func fingerprint(b cert.Bundle, it cert.Item, n int) string {
	if it.Cert == nil {
		return ""
	}
	h := sha256.New()
	h.Write(it.Cert.Raw)
	h.Write([]byte{0})
	h.Write([]byte(b.Source.String()))
	h.Write([]byte{0})
	var ib [4]byte
	ib[0] = byte(it.Index >> 24)
	ib[1] = byte(it.Index >> 16)
	ib[2] = byte(it.Index >> 8)
	ib[3] = byte(it.Index)
	h.Write(ib[:])
	sum := h.Sum(nil)
	if n <= 0 || n > len(sum)*2 {
		n = 8
	}
	return hex.EncodeToString(sum)[:n]
}

func splitNS(loc string) (string, string) {
	i := strings.IndexByte(loc, '/')
	if i < 0 {
		return "", loc
	}
	return loc[:i], loc[i+1:]
}

func serialString(it cert.Item) string {
	if it.Cert == nil || it.Cert.SerialNumber == nil {
		return ""
	}
	return it.Cert.SerialNumber.String()
}

// schema is the unified label schema. All x509_cert_* metrics share this
// schema; values irrelevant to the source kind are empty strings.
type schema struct {
	names                []string
	issFields            []string
	subFields            []string
	exposedSecretLabels  []string
	exposedCfgmapLabels  []string
	includeDiscriminator bool
	// indexes used during values-getter
	idxFilename, idxFilepath                 int
	idxEmbeddedKind, idxEmbeddedKey          int
	idxSecretNS, idxSecretName, idxSecretKey int
	idxCMNS, idxCMName, idxCMKey             int
	idxSerial                                int
	idxIssuerStart, idxSubjectStart          int
	idxSecretLabelStart, idxCMLabelStart     int
	idxDiscriminator                         int
}

// newSchema builds the unified label schema with a deterministic order.
func newSchema(opts LabelOptions, exposedSecretLabels, exposedCfgmapLabels []string, includeDisc bool) *schema {
	s := &schema{
		issFields:            dnFields(opts.IssuerFields),
		subFields:            dnFields(opts.SubjectFields),
		exposedSecretLabels:  exposedSecretLabels,
		exposedCfgmapLabels:  exposedCfgmapLabels,
		includeDiscriminator: includeDisc,
	}
	add := func(n string) int {
		s.names = append(s.names, n)
		return len(s.names) - 1
	}
	s.idxFilename = add("filename")
	s.idxFilepath = add("filepath")
	s.idxEmbeddedKind = add("embedded_kind")
	s.idxEmbeddedKey = add("embedded_key")
	s.idxSecretNS = add("secret_namespace")
	s.idxSecretName = add("secret_name")
	s.idxSecretKey = add("secret_key")
	s.idxCMNS = add("configmap_namespace")
	s.idxCMName = add("configmap_name")
	s.idxCMKey = add("configmap_key")
	s.idxSerial = add("serial_number")
	s.idxIssuerStart = len(s.names)
	for _, f := range s.issFields {
		add("issuer_" + f)
	}
	s.idxSubjectStart = len(s.names)
	for _, f := range s.subFields {
		add("subject_" + f)
	}
	s.idxSecretLabelStart = len(s.names)
	for _, l := range exposedSecretLabels {
		add("secret_label_" + sanitiseLabel(l))
	}
	s.idxCMLabelStart = len(s.names)
	for _, l := range exposedCfgmapLabels {
		add("configmap_label_" + sanitiseLabel(l))
	}
	if includeDisc {
		s.idxDiscriminator = add("discriminator")
	} else {
		s.idxDiscriminator = -1
	}
	return s
}

// values builds the values slice for a single Item in a Bundle. The
// caller fills in the discriminator after collision-resolution.
func (s *schema) values(b cert.Bundle, it cert.Item, opts LabelOptions) []string {
	v := make([]string, len(s.names))
	switch b.Source.Kind {
	case cert.KindFile:
		v[s.idxFilename] = filepath.Base(b.Source.Location)
		v[s.idxFilepath] = trimPath(b.Source.Location, opts.TrimPathComponents)
	case cert.KindKubeconfig:
		v[s.idxFilename] = filepath.Base(b.Source.Location)
		v[s.idxFilepath] = trimPath(b.Source.Location, opts.TrimPathComponents)
		v[s.idxEmbeddedKind] = b.Source.Attributes["embedded_kind"]
		v[s.idxEmbeddedKey] = b.Source.Attributes["embedded_key"]
	case cert.KindKubeSecret:
		ns, name := splitNS(b.Source.Location)
		v[s.idxSecretNS] = ns
		v[s.idxSecretName] = name
		v[s.idxSecretKey] = b.Source.Key
	case cert.KindKubeConfigMap:
		ns, name := splitNS(b.Source.Location)
		v[s.idxCMNS] = ns
		v[s.idxCMName] = name
		v[s.idxCMKey] = b.Source.Key
	}
	v[s.idxSerial] = serialString(it)
	if it.Cert != nil {
		for i, f := range s.issFields {
			v[s.idxIssuerStart+i] = dnValue(it.Cert.Issuer, f)
		}
		for i, f := range s.subFields {
			v[s.idxSubjectStart+i] = dnValue(it.Cert.Subject, f)
		}
	}
	if b.Source.Kind == cert.KindKubeSecret {
		for i, l := range s.exposedSecretLabels {
			v[s.idxSecretLabelStart+i] = b.Source.Attributes[cert.AttrSecretLabelPrefix+l]
		}
	}
	if b.Source.Kind == cert.KindKubeConfigMap {
		for i, l := range s.exposedCfgmapLabels {
			v[s.idxCMLabelStart+i] = b.Source.Attributes[cert.AttrConfigMapLabelPrefix+l]
		}
	}
	return v
}
