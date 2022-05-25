package internal

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/yalp/jsonpath"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
)

// YAMLCertRef : Contains information to access certificates in yaml files
type YAMLCertRef struct {
	CertMatchExpr string
	IDMatchExpr   string
	Format        YAMLCertFormat
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
		CertMatchExpr: "$.clusters[:].cluster[\"certificate-authority-data\"]",
		IDMatchExpr:   "$.clusters[:].name",
		Format:        YAMLCertFormatBase64,
	},
	{
		CertMatchExpr: "$.clusters[:].cluster[\"certificate-authority\"]",
		IDMatchExpr:   "$.clusters[:].name",
		Format:        YAMLCertFormatFile,
	},
	{
		CertMatchExpr: "$.users[:].user[\"client-certificate-data\"]",
		IDMatchExpr:   "$.users[:].name",
		Format:        YAMLCertFormatBase64,
	},
	{
		CertMatchExpr: "$.users[:].user[\"client-certificate\"]",
		IDMatchExpr:   "$.users[:].name",
		Format:        YAMLCertFormatFile,
	},
}

type certificateRef struct {
	path          string
	format        certificateFormat
	certificates  []*parsedCertificate
	userIDs       []string
	yamlPaths     []YAMLCertRef
	kubeSecret    v1.Secret
	kubeSecretKey string
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

func readAndParseYAMLFile(filePath string, yamlPaths []YAMLCertRef) ([]*parsedCertificate, error) {
	output := []*parsedCertificate{}

	for _, exprs := range yamlPaths {
		rawCerts, err := searchYAMLFile(filePath, exprs.CertMatchExpr)
		if err != nil {
			return nil, err
		}
		if len(rawCerts) == 0 {
			continue
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

		rawUserIDs, err := searchYAMLFile(filePath, exprs.IDMatchExpr)
		if err != nil {
			return nil, err
		}

		userIDs := []string{}
		for _, userID := range strings.Split(string(rawUserIDs), "\n") {
			if userID != "" {
				userIDs = append(userIDs, userID)
			}
		}
		if len(userIDs) != len(certs) {
			return nil, fmt.Errorf("failed to parse some labels in %s (got %d IDs but %d certs for \"%s\")", filePath, len(userIDs), len(certs), exprs.IDMatchExpr)
		}

		for index, cert := range certs {
			output = append(output, &parsedCertificate{
				cert:        cert,
				userID:      userIDs[index],
				yqMatchExpr: exprs.CertMatchExpr,
			})
		}
	}

	return output, nil
}

func searchYAMLFile(filename, expr string) (string, error) {
	var raw interface{}

	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}

	err = yaml.NewDecoder(file).Decode(&raw)
	if err != nil {
		return "", err
	}

	results, err := jsonpath.Read(raw, expr)
	if err != nil {
		return "", nil
	}

	if texts, ok := results.([]interface{}); ok {
		var output strings.Builder

		for _, line := range texts {
			if text, ok := line.(string); ok {
				output.WriteString(text)
				output.WriteRune('\n')
			} else {
				return "", fmt.Errorf("failed to convert yaml element to string: %T", results)
			}
		}

		return output.String(), nil
	}

	return "", fmt.Errorf("failed to convert yaml element to string: %T", results)
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

	realPath, err := os.Readlink(file)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(path.Join(path.Dir(file), path.Base(realPath)))
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
