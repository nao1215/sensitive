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
