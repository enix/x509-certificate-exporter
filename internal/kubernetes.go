package internal

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
)

// ConnectToKubernetesCluster : Try connect to a cluster from inside if path is empty,
// otherwise try loading the kubeconfig at path "path"
func (exporter *Exporter) ConnectToKubernetesCluster(path string, rateLimiter flowcontrol.RateLimiter) error {
	var err error
	exporter.kubeClient, err = connectToKubernetesCluster(path, false, rateLimiter)
	return err
}

func (exporter *Exporter) parseAllKubeSecrets() ([]*certificateRef, []error) {
	output := []*certificateRef{}
	outputErrors := []error{}

	namespaces, err := exporter.listNamespacesToWatch()
	if err != nil {
		outputErrors = append(outputErrors, fmt.Errorf("failed to list namespaces: %s", err.Error()))
		return output, outputErrors
	}

	for _, namespace := range namespaces {
		secrets, err := exporter.getWatchedSecrets(namespace)
		if err != nil {
			outputErrors = append(outputErrors, fmt.Errorf("failed to fetch secrets from namespace \"%s\": %s", namespace, err.Error()))
			continue
		}

		for _, secret := range secrets {
			for _, secretType := range exporter.KubeSecretTypes {
				typeAndKey := strings.Split(secretType, ":")

				if secret.Type == v1.SecretType(typeAndKey[0]) && len(secret.Data[typeAndKey[1]]) > 0 {
					output = append(output, &certificateRef{
						path:          fmt.Sprintf("k8s/%s/%s", namespace, secret.GetName()),
						format:        certificateFormatKubeSecret,
						kubeSecret:    secret,
						kubeSecretKey: typeAndKey[1],
					})
				}
			}
		}
	}

	return output, outputErrors
}

func (exporter *Exporter) listNamespacesToWatch() ([]string, error) {
	includedNamespaces := exporter.KubeIncludeNamespaces

	if len(includedNamespaces) < 1 {
		allNamespaces, err := exporter.kubeClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return nil, err
		}

		for _, ns := range allNamespaces.Items {
			includedNamespaces = append(includedNamespaces, ns.Name)
		}
	}

	namespaces := []string{}
	for _, includeNs := range includedNamespaces {
		found := false

		for _, excludeNs := range exporter.KubeExcludeNamespaces {
			if includeNs == excludeNs {
				found = true
				break
			}
		}

		if !found {
			namespaces = append(namespaces, includeNs)
		}
	}

	return namespaces, nil
}

func (exporter *Exporter) getWatchedSecrets(namespace string) ([]v1.Secret, error) {
	cachedSecrets, cached := exporter.secretsCache.Get(namespace)
	if cached {
		return cachedSecrets.([]v1.Secret), nil
	}

	includedLabelsWithValue := map[string]string{}
	includedLabelsWithoutValue := []string{}
	for _, label := range exporter.KubeIncludeLabels {
		parts := strings.Split(label, "=")
		if len(parts) < 2 {
			includedLabelsWithoutValue = append(includedLabelsWithoutValue, label)
		} else {
			includedLabelsWithValue[parts[0]] = parts[1]
		}
	}

	excludedLabelsWithValue := map[string]string{}
	excludedLabelsWithoutValue := []string{}
	for _, label := range exporter.KubeExcludeLabels {
		parts := strings.Split(label, "=")
		if len(parts) < 2 {
			excludedLabelsWithoutValue = append(excludedLabelsWithoutValue, label)
		} else {
			excludedLabelsWithValue[parts[0]] = parts[1]
		}
	}

	labelSelector := metav1.LabelSelector{MatchLabels: includedLabelsWithValue}
	secrets, err := exporter.kubeClient.CoreV1().Secrets(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
	})
	if err != nil {
		return nil, err
	}

	filteredSecrets, err := exporter.filterSecrets(secrets.Items, includedLabelsWithoutValue, excludedLabelsWithoutValue, excludedLabelsWithValue)
	if err != nil {
		return nil, err
	}

	shrinkedSecrets := []v1.Secret{}
	for _, secret := range filteredSecrets {
		shrinkedSecrets = append(shrinkedSecrets, exporter.shrinkSecret(secret))
	}

	halfDuration := float64(exporter.MaxCacheDuration.Nanoseconds()) / 2
	cacheDuration := halfDuration*float64(rand.Float64()) + halfDuration
	exporter.secretsCache.Set(namespace, shrinkedSecrets, time.Duration(cacheDuration))
	return shrinkedSecrets, nil
}

func (exporter *Exporter) filterSecrets(secrets []v1.Secret, includedLabels, excludedLabels []string, excludedLabelsWithValue map[string]string) ([]v1.Secret, error) {
	filteredSecrets := []v1.Secret{}

	for _, secret := range secrets {
		hasIncludedType, err := exporter.checkHasIncludedType(&secret)
		if err != nil {
			return nil, err
		}

		if !hasIncludedType {
			continue
		}

		validKeyCount := 0
		for _, expectedKey := range includedLabels {
			for key := range secret.GetLabels() {
				if key == expectedKey {
					validKeyCount++
					break
				}
			}
		}

		forbiddenKeyCount := 0
		for _, forbiddenKey := range excludedLabels {
			for key := range secret.GetLabels() {
				if key == forbiddenKey {
					forbiddenKeyCount++
					break
				}
			}
		}

		for forbiddenKey, forbiddenValue := range excludedLabelsWithValue {
			for key, value := range secret.GetLabels() {
				if key == forbiddenKey && value == forbiddenValue {
					forbiddenKeyCount++
					break
				}
			}
		}

		if validKeyCount >= len(includedLabels) && forbiddenKeyCount == 0 {
			filteredSecrets = append(filteredSecrets, secret)
		}
	}

	return filteredSecrets, nil
}

func (exporter *Exporter) checkHasIncludedType(secret *v1.Secret) (bool, error) {
	for _, secretType := range exporter.KubeSecretTypes {
		typeAndKey := strings.Split(secretType, ":")

		if len(typeAndKey) != 2 {
			return false, fmt.Errorf("malformed kube secret type: \"%s\"", secretType)
		}

		if secret.Type == v1.SecretType(typeAndKey[0]) && len(secret.Data[typeAndKey[1]]) > 0 {
			return true, nil
		}
	}

	return false, nil
}

func (exporter *Exporter) shrinkSecret(secret v1.Secret) v1.Secret {
	result := v1.Secret{
		Type: secret.Type,
		Data: map[string][]byte{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
	}

	for _, secretType := range exporter.KubeSecretTypes {
		typeAndKey := strings.Split(secretType, ":")
		if secret.Type == v1.SecretType(typeAndKey[0]) && len(secret.Data[typeAndKey[1]]) > 0 {
			result.Data[typeAndKey[1]] = secret.Data[typeAndKey[1]]
		}
	}

	return result
}

func connectToKubernetesCluster(kubeconfigPath string, insecure bool, rateLimiter flowcontrol.RateLimiter) (*kubernetes.Clientset, error) {
	config, err := parseKubeConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}

	if insecure {
		config.TLSClientConfig.Insecure = true
		config.TLSClientConfig.CAData = nil
	}

	if rateLimiter != nil {
		config.RateLimiter = rateLimiter
	}

	return getKubeClient(config)
}

func parseKubeConfig(kubeconfigPath string) (*rest.Config, error) {
	var config *rest.Config
	var err error

	if len(kubeconfigPath) > 0 {
		log.Infof("using kubeconfig file: %s", kubeconfigPath)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		log.Info("no kubeconfig file provided, attempting to load in-cluster configuration")
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, err
	}
	log.Infof("loaded configuration, API server is at %s", config.Host)

	return config, nil
}

func getKubeClient(config *rest.Config) (*kubernetes.Clientset, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get k8s client")
	}

	log.Info("fetching API server version")
	serverVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get Kubernetes API server version")
	}
	log.Infof("kubernetes server version is %s", serverVersion.GitVersion)

	return kubeClient, nil
}
