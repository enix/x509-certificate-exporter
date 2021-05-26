package internal

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
