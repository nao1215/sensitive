package detect

import (
	"bytes"
	"strings"
	"unicode"

	"github.com/nao1215/embargo/internal/ascii"
)

// numericLogContext caches each hostname suffix during a left-to-right scan.
// Every suffix is traversed once, even when many numeric candidates share it.
type numericLogContext struct{ end, lastDot int }

// fragment rejects decimal tails, signed identifier suffixes, and
// numeric components of hostnames. Checksums alone cannot distinguish these.
func (c *numericLogContext) fragment(data []byte, start, end int) bool {
	if start >= 2 && ((data[start-1] == '.' && ascii.IsDigit(data[start-2])) || (data[start-1] == '-' && data[start-2] == '_')) {
		return true
	}
	if end < len(data) && data[end] == '.' && end+1 < len(data) && ascii.IsAlphaNum(data[end+1]) {
		return true
	}
	if end+1 < len(data) && data[end] == '-' && ascii.IsAlpha(data[end+1]) {
		return c.hostnameComponent(data, end)
	}
	return false
}

// hostnameComponent reports whether the hyphenated suffix at end reaches a
// later dot, scanning each suffix once and reusing it for later candidates.
func (c *numericLogContext) hostnameComponent(data []byte, end int) bool {
	if end >= c.end {
		c.lastDot = -1
		c.end = end + 2 //nolint:mnd // Skip the checked hyphen and first letter.
		for c.end < len(data) && (ascii.IsAlphaNum(data[c.end]) || data[c.end] == '-' || data[c.end] == '.') {
			if data[c.end] == '.' {
				c.lastDot = c.end
			}
			c.end++
		}
	}
	return c.lastDot > end
}

func operationalNumberContext(data []byte, start int) bool {
	if start > 0 && data[start-1] == '-' {
		start--
	}
	before := bytes.TrimRightFunc(data[:start], unicode.IsSpace)
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
		if !isIdentifierByte(b) && b != '.' && b != '$' {
			return false
		}
		upper = upper || ascii.IsUpper(b)
	}
	if !upper {
		return false
	}
	for _, b := range []byte(value[split+1:]) {
		if !ascii.IsHexDigit(b) {
			return false
		}
	}
	return true
}

func registerSlot(data []byte, start, end int) bool {
	const contextBytes = 128
	before := data[max(0, start-contextBytes):start]
	if len(before) < 3 || before[len(before)-1] != '=' || !bytes.Contains(before, []byte("syscall=")) {
		return false
	}
	slot := assignmentKey(before, len(before)-1)
	if len(slot) != 2 || slot[0] != 'a' || !ascii.IsDigit(slot[1]) {
		return false
	}
	for _, b := range data[start:end] {
		if !ascii.IsHexDigit(b) {
			return false
		}
	}
	return true
}

func invalidUserSlot(data []byte, start int) bool {
	const contextBytes = 32
	before := bytes.TrimSpace(data[max(0, start-contextBytes):start])
	const label = "invalid user"
	return len(before) >= len(label) && bytes.EqualFold(before[len(before)-len(label):], []byte(label)) && (len(before) == len(label) || !isTokenByte(before[len(before)-len(label)-1]))
}

func hardwareWireSlot(data []byte, start int) bool {
	const contextBytes = 128
	before := bytes.TrimSpace(data[max(0, start-contextBytes):start])
	const wire = "wire,"
	if !bytes.HasSuffix(before, []byte(wire)) {
		return false
	}
	return bytes.Contains(before, []byte("warning for "))
}

func exceptionCounter(data []byte, end int) bool {
	const unit = "double-hummer alignment exceptions"
	after := bytes.TrimLeft(data[end:], " \t")
	return len(after) < len(data[end:]) && bytes.HasPrefix(after, []byte(unit)) && (len(after) == len(unit) || !isTokenByte(after[len(unit)]))
}

func logSequence(data []byte, start int) bool {
	const prefix = "log."
	return start >= len(prefix) && string(data[start-len(prefix):start]) == prefix && (start == len(prefix) || !isTokenByte(data[start-len(prefix)-1]))
}

// ARN has partition, service, region and account fields before its resource.
func arnAccount(data []byte, start, end int) bool {
	if end >= len(data) || data[end] != ':' || end-start != 12 {
		return false
	}
	left := arnStart(data, start)
	if left > 0 && ascii.IsAlphaNum(data[left-1]) {
		return false
	}
	fields := bytes.Split(data[left:start], []byte(":"))
	return len(fields) == 5 && string(fields[0]) == "arn" && awsPartition(fields[1]) && len(fields[2]) > 0 && len(fields[4]) == 0
}

// arnStart walks left from an account candidate to the "arn" prefix four
// separators back, stopping early at a URL delimiter, assignment or bracket.
func arnStart(data []byte, start int) int {
	left := start
	colons := 0
	for left > 0 && !urlDelimiter(data[left-1]) && data[left-1] != '=' && data[left-1] != '[' {
		left--
		if data[left] == ':' {
			colons++
			const arnSeparators = 4
			if colons == arnSeparators {
				left = max(0, left-len("arn"))
				break
			}
		}
	}
	return left
}

// awsPartition reports whether an ARN partition field names an AWS partition.
func awsPartition(field []byte) bool {
	switch string(field) {
	case "aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f":
		return true
	}
	return false
}
