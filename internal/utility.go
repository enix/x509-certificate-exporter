package internal

import (
	"regexp"
)

func unique(data []*certificateRef) []*certificateRef {
	output := []*certificateRef{}
	seen := map[string]bool{}

	for _, elem := range data {
		if !seen[elem.path+elem.kubeSecretKey] {
			seen[elem.path+elem.kubeSecretKey] = true
			output = append(output, elem)
		}
	}

	return output
}

func getMatchingKeys(secretKeyValues map[string][]byte, pattern string) ([]string, error) {
	keys := make([]string, 0, len(secretKeyValues))
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return keys, err
	}

	for key := range secretKeyValues {
		if regex.MatchString(key) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}
