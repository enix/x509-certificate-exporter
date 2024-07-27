package internal

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/yalp/jsonpath"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	"software.sslmate.com/src/go-pkcs12"
)

// YAMLCertRef : Contains information to access certificates in yaml files
type YAMLCertRef struct {
	BasePathMatchExpr string
	CertMatchSubExpr  string
	IDMatchSubExpr    string
	Format            YAMLCertFormat
}

// YAMLCertFormat : Type of cert encoding in YAML files
type YAMLCertFormat int

// YAMLCertFormat : Impl
const (
	YAMLCertFormatFile   YAMLCertFormat = iota
	YAMLCertFormatBase64                = iota
)

// DefaultYamlPaths : Pre-written paths for some k8s config files
var DefaultYamlPaths = []YAMLCertRef{
	{
		BasePathMatchExpr: "$.clusters",
		CertMatchSubExpr:  "$.cluster[\"certificate-authority-data\"]",
		IDMatchSubExpr:    "$.name",
		Format:            YAMLCertFormatBase64,
	},
	{
		BasePathMatchExpr: "$.clusters",
		CertMatchSubExpr:  "$.cluster[\"certificate-authority\"]",
		IDMatchSubExpr:    "$.name",
		Format:            YAMLCertFormatFile,
	},
	{
		BasePathMatchExpr: "$.users",
		CertMatchSubExpr:  "$.user[\"client-certificate-data\"]",
		IDMatchSubExpr:    "$.name",
		Format:            YAMLCertFormatBase64,
	},
	{
		BasePathMatchExpr: "$.users",
		CertMatchSubExpr:  "$.user[\"client-certificate\"]",
		IDMatchSubExpr:    "$.name",
		Format:            YAMLCertFormatFile,
	},
}

type certificateRef struct {
	path          string
	format        certificateFormat
	certificates  []*parsedCertificate
	yamlPaths     []YAMLCertRef
	kubeSecret    v1.Secret
	kubeSecretKey string
	p12Password   string

}

type parsedCertificate struct {
	cert        *x509.Certificate
	userID      string
	yqMatchExpr string
}

type certificateError struct {
	err error
	ref *certificateRef
}

type certificateFormat int

const (
	certificateFormatPEM        certificateFormat = iota
	certificateFormatYAML                         = iota
	certificateFormatKubeSecret                   = iota
	certificateFormatP12                          = iota
)

func (cert *certificateRef) parse() error {
	var err error

	switch cert.format {
	case certificateFormatPEM:
		cert.certificates, err = readAndParsePEMFile(cert.path)
	case certificateFormatYAML:
		cert.certificates, err = readAndParseYAMLFile(cert.path, cert.yamlPaths)
	case certificateFormatKubeSecret:
		cert.certificates, err = readAndParseKubeSecret(&cert.kubeSecret, cert.kubeSecretKey)
	case certificateFormatP12:
		cert.certificates, err = readAndParsePasswordPkcsFile(cert.path, cert.p12Password)
	}

	return err
}

func readAndParsePEMFile(path string) ([]*parsedCertificate, error) {
	contents, err := readFile(path)
	if err != nil {
		return nil, err
	}

	output := []*parsedCertificate{}
	certs, err := parsePEM(contents)
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		output = append(output, &parsedCertificate{cert: cert})
	}

	return output, nil
}

func readAndParsePasswordPkcsFile(path string, password string) ([]*parsedCertificate, error) {
        contents, err := readFile(path)
        if err != nil {
               return nil, err
        }

        output := []*parsedCertificate{}
        // keystore p12
        _, cert, err := pkcs12.Decode(contents, password)
	if err == nil {
                output = append(output, &parsedCertificate{cert: cert})
		return output, nil
	}

	// truststore p12
        certs, err := pkcs12.DecodeTrustStore(contents, password)
        if err != nil {
                return nil, err
        }

        for _, cert := range certs {
                output = append(output, &parsedCertificate{cert: cert})
        }
        return output, nil
}

func readAndParseYAMLFile(filePath string, yamlPaths []YAMLCertRef) ([]*parsedCertificate, error) {
	output := []*parsedCertificate{}

	for _, exprs := range yamlPaths {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		var raw interface{}
		err = yaml.NewDecoder(file).Decode(&raw)
		if err != nil {
			return nil, err
		}

		entries, err := jsonpath.Read(raw, exprs.BasePathMatchExpr)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries.([]interface{}) {
			line, err := jsonpath.Read(entry, exprs.CertMatchSubExpr)
			if err != nil {
				continue
			}
			id, err := jsonpath.Read(entry, exprs.IDMatchSubExpr)
			if err != nil {
				continue
			}
			rawCerts, ok := line.(string)
			if !ok {
				return nil, err
			}

			var decodedCerts []byte
			if exprs.Format == YAMLCertFormatBase64 {
				decodedCerts = []byte{}
				encodedCerts := strings.Split(rawCerts, "\n")

				for _, encodedCert := range encodedCerts {
					decodedCert, err := base64.StdEncoding.DecodeString(encodedCert)
					if err != nil {
						return nil, err
					}

					decodedCerts = append(decodedCerts, decodedCert...)
					decodedCerts = append(decodedCerts, '\n')
				}
			} else if exprs.Format == YAMLCertFormatFile {
				rawCertPaths := strings.TrimRight(string(rawCerts), "\n")

				for _, certPath := range strings.Split(rawCertPaths, "\n") {
					if !path.IsAbs(certPath) {
						certPath = path.Join(filepath.Dir(filePath), rawCertPaths)
					}

					data, err := readFile(certPath)
					if err != nil {
						return nil, err
					}

					decodedCerts = append(decodedCerts, data...)
				}
			}

			certs, err := parsePEM(decodedCerts)
			if err != nil {
				return nil, err
			}

			for index, cert := range certs {
				displayName := id.(string)
				if len(certs) > 1 {
					displayName = fmt.Sprintf("%s(%d)", id, index)
				}
				output = append(output, &parsedCertificate{
					cert:        cert,
					userID:      displayName,
					yqMatchExpr: fmt.Sprintf("%s[:]%s", exprs.BasePathMatchExpr, exprs.CertMatchSubExpr[1:]),
				})
			}
		}
	}

	return output, nil
}

func readAndParseKubeSecret(secret *v1.Secret, key string) ([]*parsedCertificate, error) {
	certs, err := parsePEM(secret.Data[key])
	if err != nil {
		return nil, err
	}

	output := []*parsedCertificate{}
	for _, cert := range certs {
		output = append(output, &parsedCertificate{
			cert: cert,
		})
	}

	return output, nil
}

func readFile(file string) ([]byte, error) {
	contents, err := os.ReadFile(file)
	if err == nil || !os.IsNotExist(err) {
		return contents, err
	}

	fsys := os.DirFS(".")
	if filepath.IsAbs(file) {
		fsys = os.DirFS("/")
	}

	realPath, err := resolveSymlink(fsys, file)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(realPath)
}

func resolveSymlink(fsys fs.FS, link string) (string, error) {
	directory := fmt.Sprintf("%v", fsys)

	symlink, err := os.Readlink(fmt.Sprintf("%s/%s", directory, link))
	if err != nil {
		return "", err
	}

	// only resolve the symlink filename, and not its full path, to stay compatible with k8s volume mounts
	// see https://github.com/enix/x509-certificate-exporter/tree/main/deploy/charts/x509-certificate-exporter#watching-symbolic-links
	return path.Join(path.Dir(link), path.Base(string(symlink))), nil
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	output := []*x509.Certificate{}

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tried to parse malformed x509 data, %s", err.Error())
		}

		output = append(output, cert)
	}

	return output, nil
}
