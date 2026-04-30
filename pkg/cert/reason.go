package cert

// Canonical reason codes for ItemError. These appear as the "reason" label
// of x509_source_errors_total, so they form a stable contract.
const (
	ReasonBadPEM             = "bad_pem"
	ReasonNoCertificateFound = "no_certificate_found"
	ReasonBadPKCS12          = "bad_pkcs12"
	ReasonBadPassphrase      = "bad_passphrase"
	ReasonReadFailed         = "read_failed"
	ReasonPermissionDenied   = "permission_denied"
	ReasonNotFound           = "not_found"
	ReasonAPIError           = "api_error"
	ReasonDecodeFailed       = "decode_failed"
	ReasonBrokenSymlink      = "broken_symlink"
	ReasonParseTimeout       = "parse_timeout"
	ReasonWalkError          = "walk_error"
)
