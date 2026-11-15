package detect

import (
	"bytes"
	"strings"
)

// numericLogFragment rejects decimal tails, signed identifier suffixes, and
// numeric components of hostnames. Checksums alone cannot distinguish these.
func numericLogFragment(data []byte, start, end int) bool {
	if start >= 2 && ((data[start-1] == '.' && isDigit(data[start-2])) || (data[start-1] == '-' && data[start-2] == '_')) {
		return true
	}
	if end < len(data) && data[end] == '.' && end+1 < len(data) && isAlphaNum(data[end+1]) {
		return true
	}
	if end+1 < len(data) && data[end] == '-' && isAlpha(data[end+1]) {
		//nolint:mnd // Skip the hyphen and first hostname letter already checked above.
		for i := end + 2; i < len(data) && (isAlphaNum(data[i]) || data[i] == '-' || data[i] == '.'); i++ {
			if data[i] == '.' {
				return true
			}
		}
	}
	return false
}

func operationalNumberContext(data []byte, start int) bool {
	if start > 0 && data[start-1] == '-' {
		start--
	}
	before := bytes.TrimSpace(data[:start])
	if len(before) == 0 || before[len(before)-1] != '=' {
		return false
	}
	key := NormalizeCredentialKey(string(assignmentKey(before, len(before)-1)))
	switch key {
	case "eventtime", "downtime", "lock", "ino":
		return true
	}
	return false
}

// Java's Class@hex and Class{hex renderings name object identities. Quoted
// credentials bypass this check; their contents are explicitly string data.
func objectReference(data []byte, start, end int) bool {
	if start > 0 && (data[start-1] == '"' || data[start-1] == '\'') {
		return false
	}
	value := string(data[start:end])
	split := strings.IndexAny(value, "@{")
	if split <= 0 || len(value)-split-1 < 1 || len(value)-split-1 > 16 {
		return false
	}
	upper := false
	for _, b := range []byte(value[:split]) {
		if !isAlphaNum(b) && b != '.' && b != '_' && b != '$' {
			return false
		}
		upper = upper || b >= 'A' && b <= 'Z'
	}
	if !upper {
		return false
	}
	for _, b := range []byte(value[split+1:]) {
		if !isHexDigit(b) {
			return false
		}
	}
	return true
}
