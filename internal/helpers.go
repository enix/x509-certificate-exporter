package exporter

func unique(data []*certificateRef) []*certificateRef {
	output := []*certificateRef{}
	seen := map[string]bool{}

	for _, elem := range data {
		if !seen[elem.path] {
			seen[elem.path] = true
			output = append(output, elem)
		}
	}

	return output
}
