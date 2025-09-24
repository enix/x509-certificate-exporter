package internal

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/pkg/errors"
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

func MatchingSecretKeys(types []KubeSecretType, secret *v1.Secret) iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, secretType := range types {
			for key := range secret.Data {
				if len(secret.Data[key]) > 0 && secretType.Matches(string(secret.Type), key) {
					if !yield(key) {
						return
					}
				}
			}
		}
	}
}

func (exporter *Exporter) parseAllKubeObjects() ([]*certificateRef, []error) {
	output := []*certificateRef{}
	outputErrors := []error{}
	readCertificatesFromSecrets := func(secrets []v1.Secret) (outputs []*certificateRef) {
		for _, secret := range secrets {
			for key := range MatchingSecretKeys(exporter.KubeSecretTypes, &secret) {
				output = append(output, &certificateRef{
					path:          fmt.Sprintf("k8s/%s/%s", secret.GetNamespace(), secret.GetName()),
					format:        certificateFormatKubeSecret,
					kubeSecret:    secret,
					kubeSecretKey: key,
				})
			}
		}
		return outputs
	}
	contains := func(needle string, haystack []string) bool {
		for _, item := range haystack {
			if needle == item {
				return true
			}
		}
		return false
	}
	readCertificatesFromConfigMaps := func(configMaps []v1.ConfigMap) (outputs []*certificateRef) {
		for _, configMap := range configMaps {
			for key := range configMap.Data {
				if contains(key, exporter.ConfigMapKeys) {
					outputs = append(outputs, &certificateRef{
						path:          fmt.Sprintf("k8s/%s/%s", configMap.GetNamespace(), configMap.GetName()),
						format:        certificateFormatKubeConfigMap,
						kubeConfigMap: configMap,
						kubeSecretKey: key,
					})
				}
			}
		}
		return outputs
	}

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
		output = append(output, readCertificatesFromSecrets(secrets)...)

		if len(exporter.ConfigMapKeys) > 0 {
			configMaps, err := exporter.getWatchedConfigMaps(namespace)
			if err != nil {
				outputErrors = append(outputErrors, fmt.Errorf("failed to fetch configmaps from namespace \"%s\": %s", namespace, err.Error()))
				continue
			}
			output = append(output, readCertificatesFromConfigMaps(configMaps)...)
		}
	}

	return output, outputErrors
}

func (exporter *Exporter) listNamespacesToWatch() ([]string, error) {
	if len(exporter.KubeIncludeNamespaces) > 0 &&
		len(exporter.KubeIncludeNamespaceLabels) == 0 &&
		len(exporter.KubeExcludeNamespaceLabels) == 0 {
		slog.Debug("skipping namespace list API call; namespace existence is not validated when using --include-namespace without label filters")
		result := []string{}
		for _, ns := range exporter.KubeIncludeNamespaces {
			if !slices.Contains(exporter.KubeExcludeNamespaces, ns) {
				result = append(result, ns)
			}
		}
		return result, nil
	}

	_, includedLabelsWithValue := exporter.prepareLabelFilters(exporter.KubeIncludeNamespaceLabels)
	labelSelector := metav1.LabelSelector{MatchLabels: includedLabelsWithValue}
	namespaces, err := exporter.kubeClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
	})
	if err != nil {
		return nil, err
	}

	return exporter.filterNamespaces(namespaces.Items), nil
}

func (exporter *Exporter) filterNamespaces(namespaces []v1.Namespace) []string {
	filteredNamespaces := []*v1.Namespace{}
	for _, namespace := range namespaces {
		found := false
		for _, includeNs := range exporter.KubeIncludeNamespaces {
			if namespace.Name == includeNs {
				found = true
				break
			}
		}

		if len(exporter.KubeIncludeNamespaces) > 0 && !found {
			continue
		}

		found = false
		for _, excludeNs := range exporter.KubeExcludeNamespaces {
			if namespace.Name == excludeNs {
				found = true
				break
			}
		}

		if !found {
			filteredNamespaces = append(filteredNamespaces, &namespace)
		}
	}

	includedLabels, _ := exporter.prepareLabelFilters(exporter.KubeIncludeNamespaceLabels)
	excludedLabels, excludedLabelsWithValue := exporter.prepareLabelFilters(exporter.KubeExcludeNamespaceLabels)
	filteredNamespaces = filterObjects(filteredNamespaces, includedLabels, excludedLabels, excludedLabelsWithValue)

	namespacesNames := []string{}
	for _, namespace := range filteredNamespaces {
		namespacesNames = append(namespacesNames, namespace.Name)
	}

	return namespacesNames
}

func (exporter *Exporter) prepareLabelFilters(labels []string) ([]string, map[string]string) {
	labelsWithValue := map[string]string{}
	labelsWithoutValue := []string{}

	for _, label := range labels {
		parts := strings.Split(label, "=")
		if len(parts) < 2 {
			labelsWithoutValue = append(labelsWithoutValue, label)
		} else {
			labelsWithValue[parts[0]] = parts[1]
		}
	}

	return labelsWithoutValue, labelsWithValue
}

func (exporter *Exporter) getWatchedConfigMaps(namespace string) ([]v1.ConfigMap, error) {
	cachedConfigMaps, cached := exporter.configMapsCache.Get(namespace)
	if cached {
		return cachedConfigMaps.([]v1.ConfigMap), nil
	}
	configMapsList, err := exporter.kubeClient.CoreV1().ConfigMaps(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	configMaps := configMapsList.Items
	halfDuration := float64(exporter.MaxCacheDuration.Nanoseconds()) / 2
	cacheDuration := halfDuration*float64(rand.Float64()) + halfDuration
	exporter.configMapsCache.Set(namespace, configMaps, time.Duration(cacheDuration))
	return configMaps, nil
}

func (exporter *Exporter) getWatchedSecrets(namespace string) ([]v1.Secret, error) {
	cachedSecrets, cached := exporter.secretsCache.Get(namespace)
	if cached {
		return cachedSecrets.([]v1.Secret), nil
	}

	_, includedLabelsWithValue := exporter.prepareLabelFilters(exporter.KubeIncludeLabels)
	labelSelector := metav1.LabelSelector{MatchLabels: includedLabelsWithValue}
	secrets, err := exporter.kubeClient.CoreV1().Secrets(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
	})
	if err != nil {
		return nil, err
	}

	filteredSecrets, err := exporter.filterSecrets(secrets.Items)
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

func (exporter *Exporter) filterSecrets(secrets []v1.Secret) ([]v1.Secret, error) {
	filteredSecrets := []*v1.Secret{}

	includedLabels, _ := exporter.prepareLabelFilters(exporter.KubeIncludeLabels)
	excludedLabels, excludedLabelsWithValue := exporter.prepareLabelFilters(exporter.KubeExcludeLabels)

	for _, secret := range secrets {
		hasIncludedType, err := exporter.checkHasIncludedType(&secret)
		if err != nil {
			return nil, err
		}

		if !hasIncludedType {
			continue
		}

		filteredSecrets = append(filteredSecrets, &secret)
	}

	filteredSecrets = filterObjects(filteredSecrets, includedLabels, excludedLabels, excludedLabelsWithValue)
	for i, filteredSecret := range filteredSecrets {
		secrets[i] = *filteredSecret
	}

	return secrets[:len(filteredSecrets)], nil
}

func (exporter *Exporter) checkHasIncludedType(secret *v1.Secret) (bool, error) {
	for range MatchingSecretKeys(exporter.KubeSecretTypes, secret) {
		return true, nil
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
	for key := range MatchingSecretKeys(exporter.KubeSecretTypes, &secret) {
		result.Data[key] = secret.Data[key]
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
		slog.Info("Using kubeconfig file", "path", kubeconfigPath)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		slog.Info("Attempting to load in-cluster Kubernetes configuration")
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, err
	}
	slog.Info("Loaded Kubernetes configuration", "apiserver_host", config.Host)

	return config, nil
}

func getKubeClient(config *rest.Config) (*kubernetes.Clientset, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get k8s client")
	}

	slog.Info("Fetching Kubernetes API server version")
	serverVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get Kubernetes API server version")
	}
	slog.Info("Got Kubernetes API server version", "apiserver_version", serverVersion.GitVersion)

	return kubeClient, nil
}

func filterObjects[T metav1.Object](objects []T, includedLabels []string, excludedLabels []string, excludedLabelsWithValue map[string]string) []T {
	filteredObjects := []T{}

	for _, object := range objects {
		validKeyCount := 0
		for _, expectedKey := range includedLabels {
			for key := range object.GetLabels() {
				if key == expectedKey {
					validKeyCount++
					break
				}
			}
		}

		forbiddenKeyCount := 0
		for _, forbiddenKey := range excludedLabels {
			for key := range object.GetLabels() {
				if key == forbiddenKey {
					forbiddenKeyCount++
					break
				}
			}
		}

		for forbiddenKey, forbiddenValue := range excludedLabelsWithValue {
			for key, value := range object.GetLabels() {
				if key == forbiddenKey && value == forbiddenValue {
					forbiddenKeyCount++
					break
				}
			}
		}

		if validKeyCount >= len(includedLabels) && forbiddenKeyCount == 0 {
			filteredObjects = append(filteredObjects, object)
		}
	}

	return filteredObjects
}
