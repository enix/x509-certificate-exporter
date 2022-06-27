module github.com/enix/x509-certificate-exporter/v3

go 1.16

require (
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pborman/getopt/v2 v2.1.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.10.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.25.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/yalp/jsonpath v0.0.0-20180802001716-5cc68e5049a0
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.21.1
)

replace golang.org/x/crypto => golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f
