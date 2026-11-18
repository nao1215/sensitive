package detect

import (
	"bytes"
	"math"
	"strings"

	"github.com/nao1215/embargo/internal/ascii"
)

// HighEntropy implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindHighEntropy.
type HighEntropy struct{}

// Name returns the high entropy family.
func (*HighEntropy) Name() DetectorName { return "high_entropy" }

// Hints returns nil because unprefixed tokens have no mandatory substring.
func (*HighEntropy) Hints() [][]byte { return nil }

// Scan returns uncertain high-entropy candidates, including public random IDs
// whose semantics cannot be inferred. A minimum confidence above 0.3 excludes them.
func (d *HighEntropy) Scan(data []byte) []Finding {
	var out []Finding
	for start := 0; start < len(data); {
		if !entropyByte(data[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(data) && entropyByte(data[end]) {
			end++
		}
		if !entropyLocation(data, start, end) && entropyCandidate(data[start:end]) && !ordinaryIDContext(data, start) && !kubernetesGeneratedName(data[start:end]) {
			//nolint:mnd // Uncontextualized entropy is deliberately below masking precision thresholds.
			out = append(out, Finding{DetectorName: d.Name(), Start: start, End: end, Confidence: 0.3})
		}
		start = end
	}
	return out
}

func entropyByte(b byte) bool { return isTokenByte(b) || b == '+' }

// A slash ends a candidate. Adjacent path separators or dotted components are
// locations, even when a single component has enough entropy to look random.
func entropyLocation(data []byte, start, end int) bool {
	if start > 0 {
		b := data[start-1]
		if b == '/' || b == '\\' || (b == '.' && start > 1 && isTokenByte(data[start-2])) {
			return true
		}
	}
	if end < len(data) {
		b := data[end]
		if b == '/' || b == '\\' || (b == '.' && end+1 < len(data) && isTokenByte(data[end+1])) {
			return true
		}
	}
	return false
}

func entropyCandidate(data []byte) bool {
	const minLength, maxLength, minEntropy = 32, 256, 4.5
	if len(data) < minLength || len(data) > maxLength {
		return false
	}
	var counts [256]int
	var lower, upper, digit, symbol bool
	for _, b := range data {
		counts[b]++
		switch {
		case ascii.IsLower(b):
			lower = true
		case ascii.IsUpper(b):
			upper = true
		case ascii.IsDigit(b):
			digit = true
		default:
			symbol = true
		}
	}
	const minimumClasses = 3
	classes := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			classes++
		}
	}
	if classes < minimumClasses {
		return false
	}
	score := 0.0
	for _, count := range &counts {
		if count != 0 {
			p := float64(count) / float64(len(data))
			score -= p * math.Log2(p)
		}
	}
	return score >= minEntropy
}

func ordinaryIDContext(data []byte, start int) bool {
	const contextBytes = 64
	before := strings.TrimSpace(string(data[max(0, start-contextBytes):start]))
	before = strings.TrimRight(before, "\"' ")
	if before == "" {
		return false
	}
	last := before[len(before)-1]
	if last != '=' && last != ':' {
		return false
	}
	key := NormalizeCredentialKey(string(assignmentKey([]byte(before), len(before)-1)))
	switch key {
	case "id", "requestid", "traceid", "spanid", "commit", "sha", "hash", "checksum", "uuid":
		return true
	}
	// Pagination cursors, such as the Kubernetes continue parameter and the
	// GraphQL endCursor, encode server-side list state that the same client
	// sends back; they are opaque but not credentials.
	return key == "continue" || strings.HasSuffix(key, "cursor")
}

// kubernetesRandomAlphabet is the alphabet of Kubernetes generated name
// suffixes (k8s.io/apimachinery/pkg/util/rand), which omits vowels and the
// digits 0, 1 and 3.
const kubernetesRandomAlphabet = "bcdfghjklmnpqrstvwxz2456789"

// kubernetesGeneratedName reports a lowercase DNS name such as a pod name
// (word-<template hash>-<five random characters>). Such names are public
// resource identifiers, not secrets, though their suffixes raise entropy.
func kubernetesGeneratedName(value []byte) bool {
	const suffixLength = 5
	cut := bytes.LastIndexByte(value, '-')
	if cut <= 0 || len(value)-cut-1 != suffixLength {
		return false
	}
	for _, b := range value[cut+1:] {
		if strings.IndexByte(kubernetesRandomAlphabet, b) < 0 {
			return false
		}
	}
	word := false
	for segment := range bytes.SplitSeq(value[:cut], []byte("-")) {
		letters := len(segment) > 1
		for _, b := range segment {
			if !ascii.IsLower(b) && !ascii.IsDigit(b) {
				return false
			}
			letters = letters && ascii.IsLower(b)
		}
		word = word || letters
	}
	return word
}
