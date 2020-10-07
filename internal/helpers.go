package exporter

func unique(data []string) []string {
	output := []string{}
	seen := map[string]bool{}

	for _, elem := range data {
		if !seen[elem] {
			seen[elem] = true
			output = append(output, elem)
		}
	}

	return output
}
