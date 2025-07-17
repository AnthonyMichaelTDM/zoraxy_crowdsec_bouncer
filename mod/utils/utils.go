package utils

import (
	"fmt"
	"strings"
)

// ExtractHeader extracts the values of a header from the request headers map
// If the header is not found, behavior depends on the searchIfNotFound flag:
//   - If true, will search all the keys in the headers map to find a case-insensitive match
//   - If false, will return an empty string
func ExtractHeader(headers map[string][]string, key string, searchIfNotFound bool) (string, error) {
	// first, try accessing the header directly
	if values, ok := headers[key]; ok {
		if concattenated := strings.Join(values, ", "); concattenated != "" {
			return concattenated, nil
		} else {
			return "", fmt.Errorf("header %s found but has no values", key)
		}
	}

	if searchIfNotFound {
		// If not found, search for a case-insensitive match
		for k, v := range headers {
			if strings.EqualFold(k, key) && len(v) > 0 {
				return strings.Join(v, ", "), nil
			}
		}
	}

	return "", fmt.Errorf("header %s not found", key)
}
