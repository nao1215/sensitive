package embargotest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

func representations(canary []byte) [][]byte {
	// A string has no JSON marshal failures. Use both HTML and ASCII escaping.
	//nolint:errchkjson // Keep marshal errors explicit under errcheck if serialized types evolve.
	encoded, err := json.Marshal(string(canary))
	if err != nil {
		return [][]byte{canary}
	}
	needles := [][]byte{
		append([]byte(nil), canary...),
		[]byte(hex.EncodeToString(canary)),
		[]byte(strings.ToUpper(hex.EncodeToString(canary))),
		encoded[1 : len(encoded)-1],
		[]byte(fmt.Sprintf("%v", canary)),
		[]byte(strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", canary), "[]byte{"), "}")),
		[]byte(new(big.Int).SetBytes(canary).String()),
	}
	// Go quoting with and without escaping non-ASCII, and JSON written by an
	// Encoder with SetEscapeHTML(false).
	for _, quoted := range []string{strconv.QuoteToASCII(string(canary)), strconv.Quote(string(canary))} {
		needles = append(needles, []byte(quoted[1:len(quoted)-1]))
	}
	var plain bytes.Buffer
	encoder := json.NewEncoder(&plain)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(string(canary)); err == nil {
		unescaped := bytes.TrimSuffix(plain.Bytes(), []byte("\n"))
		needles = append(needles, unescaped[1:len(unescaped)-1])
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		needles = append(needles, []byte(encoding.EncodeToString(canary)))
		// Drop symbols sharing bits with the unknown prefix or suffix. The retained
		// interior includes only canary bits and works at every three-byte alignment.
		const inputBits, symbolBits, alignments = 8, 6, 3
		for shift := range alignments {
			padded := append(make([]byte, shift), canary...)
			encoded := encoding.EncodeToString(padded)
			first := (shift*inputBits + symbolBits - 1) / symbolBits
			last := len(padded) * inputBits / symbolBits
			if last > first {
				needles = append(needles, []byte(encoded[first:last]))
			}
		}
	}
	return needles
}

func containsCanary(data []byte, needles [][]byte) bool {
	for _, needle := range needles {
		if len(needle) > 0 && bytes.Contains(data, needle) {
			return true
		}
	}
	return false
}

type fragmentOption int

// WithCanaryFragments also checks every contiguous raw canary fragment of at
// least minBytes bytes. The minimum must be 16 through the final canary length.
// This opt-in policy catches long partial values and pieces on separate lines
// or sinks; it does not reconstruct smaller pieces or transform fragments.
// Choose a distinctive fake canary: matching a common fragment can reject
// unrelated output. The default checks only whole-value representations.
func WithCanaryFragments(minBytes int) Option { return fragmentOption(minBytes) }

func (o fragmentOption) apply(r *Recorder) bool {
	const smallestFragment = 16
	const largestCanary = 1024
	if int(o) < smallestFragment || int(o) > largestCanary {
		return false
	}
	r.minFragment = int(o)
	return true
}

func (r *Recorder) configureNeedles() {
	r.needles = representations(r.canary)
	if r.minFragment > len(r.canary) {
		r.failed = true
		return
	}
	if r.minFragment == 0 {
		return
	}
	// A longer raw fragment necessarily contains a minimum-length window.
	// The canary already belongs to the policy and remains immutable.
	seen := make(map[string]bool)
	for start := 0; start+r.minFragment <= len(r.canary); start++ {
		fragment := r.canary[start : start+r.minFragment]
		if !seen[string(fragment)] {
			seen[string(fragment)] = true
			r.needles = append(r.needles, fragment)
		}
	}
}
