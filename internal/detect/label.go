package detect

import "bytes"

// labelPrefix confines contextual evidence to the current field and line.
func labelPrefix(data []byte, start int) []byte {
	const radius = 48
	prefix := data[max(0, start-radius):start]
	if i := bytes.LastIndexAny(prefix, "\r\n;,{}[]"); i >= 0 {
		prefix = prefix[i+1:]
	}
	return prefix
}

// previousLabelWord returns slices of the input, without allocating on every finding.
func previousLabelWord(prefix []byte) (rest, word []byte) {
	end := len(prefix)
	for end > 0 && labelSeparator(prefix[end-1]) {
		end--
	}
	start := end
	for start > 0 && !labelSeparator(prefix[start-1]) {
		start--
	}
	return prefix[:start], prefix[start:end]
}

func labelSeparator(b byte) bool {
	switch b {
	case ' ', '\t', ':', '=', '_', '-', '"', '\'':
		return true
	default:
		return false
	}
}

func labelIs(word []byte, values ...string) bool {
	for _, value := range values {
		if bytes.EqualFold(word, []byte(value)) {
			return true
		}
	}
	return false
}

// businessConfidence preserves ambiguous numbers for callers that favor recall.
// Only an attached business label lowers confidence, never a remote keyword.
func businessConfidence(data []byte, start int, confidence float64) float64 {
	prefix := labelPrefix(data, start)
	for len(prefix) > 0 {
		rest, word := previousLabelWord(prefix)
		prefix = rest
		if labelIs(word, "id", "number", "ref", "code") {
			continue
		}
		if labelIs(word, "order", "invoice", "tracking", "version", "build", "serial", "shipment") {
			const ambiguousConfidence = .4
			return ambiguousConfidence
		}
		break
	}
	return confidence
}
