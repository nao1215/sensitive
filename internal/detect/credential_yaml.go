package detect

import (
	"bytes"
	"strings"
)

// Block scalar contents belong to the credential until indentation returns to
// the key's level. Other YAML syntax is not inferred from free text.
func credentialBlockEnd(data []byte, fieldStart, start int) int {
	if data[start] != '|' && data[start] != '>' {
		return start
	}
	line := bytes.LastIndexByte(data[:fieldStart], '\n') + 1
	indent := 0
	for line+indent < len(data) && data[line+indent] == ' ' {
		indent++
	}
	end := start + 1
	for end < len(data) && strings.ContainsRune("+-123456789 \r", rune(data[end])) {
		end++
	}
	if end == len(data) || data[end] != '\n' {
		return start
	}
	return blockScalarContentEnd(data, end+1, indent)
}

// blockScalarContentEnd consumes block scalar lines from end until a non-blank
// line returns to the key's indentation or less.
func blockScalarContentEnd(data []byte, end, indent int) int {
	for end < len(data) {
		next := end
		for next < len(data) && data[next] == ' ' {
			next++
		}
		if next < len(data) && data[next] != '\n' && data[next] != '\r' && next-end <= indent {
			break
		}
		stop := bytes.IndexByte(data[next:], '\n')
		if stop < 0 {
			return len(data)
		}
		end = next + stop + 1
	}
	return end
}
