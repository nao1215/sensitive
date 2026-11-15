package embargotest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
)

func FuzzCanary(f *testing.F) {
	f.Add([]byte("fake-canary-0123456789"), uint8(3))
	f.Add([]byte("fake-\u00e9-\x00-secret-0123456789"), uint8(7))
	f.Add([]byte("fake-\u00e9-<>&-\n-secret-0123456789"), uint8(7))
	// JSON writes \u0001 and keeps <>& with SetEscapeHTML(false); Go writes \x01.
	f.Add([]byte("fake-<>&-\x01-secret-0123456789"), uint8(5))
	f.Fuzz(func(t *testing.T, raw []byte, split uint8) {
		if len(raw) < 16 || len(raw) > 1024 {
			return
		}
		for _, needle := range stdlibEncodings(raw) {
			if len(needle) == 0 {
				continue
			}
			p := &probeTB{TB: t}
			r := New(p, WithCanary(raw))
			at := int(split) % len(needle)
			write(t, r, "out", needle[:at])
			write(t, r, "out", needle[at:])
			r.Expect("out", func([]byte) bool { return true })
			if r.Check() {
				t.Fatal("encoded canary missed across writes")
			}
			p.finish()
		}
	})
}

// stdlibEncodings writes raw with the standard library encoders that
// embargotest/doc.go promises to detect. It is built independently of
// representations so a missing needle fails the fuzz target.
func stdlibEncodings(raw []byte) [][]byte {
	unquote := func(s string) []byte { return []byte(s[1 : len(s)-1]) }
	var plain bytes.Buffer
	encoder := json.NewEncoder(&plain)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(string(raw)); err != nil {
		panic("string encoding failed")
	}
	//nolint:errchkjson // Keep marshal errors explicit under errcheck if serialized types evolve.
	marshaled, err := json.Marshal(string(raw))
	if err != nil {
		panic("string marshal failed")
	}
	return [][]byte{
		raw,
		// fmt, not encoding/hex, so the oracle uses the verbs callers write.
		[]byte(fmt.Sprintf("%x", raw)), //nolint:perfsprint // See above.
		[]byte(fmt.Sprintf("%X", raw)),
		unquote(string(marshaled)),
		unquote(strings.TrimSuffix(plain.String(), "\n")),
		unquote(fmt.Sprintf("%q", raw)),
		unquote(fmt.Sprintf("%+q", raw)),
		[]byte(fmt.Sprint(raw)), //nolint:staticcheck // The decimal byte-slice form [1 2 3] is the encoding under test.
		[]byte(new(big.Int).SetBytes(raw).String()),
		[]byte(base64.StdEncoding.EncodeToString(raw)),
		[]byte(base64.RawStdEncoding.EncodeToString(raw)),
		[]byte(base64.URLEncoding.EncodeToString(raw)),
		[]byte(base64.RawURLEncoding.EncodeToString(raw)),
	}
}

func FuzzJSONStream(f *testing.F) {
	f.Add([]byte("{"))
	f.Add([]byte("["))
	f.Add([]byte(" \n"))
	f.Add([]byte(`{"nested":`))
	f.Fuzz(func(t *testing.T, suffix []byte) {
		if len(suffix) > 4096 {
			return
		}
		data := append([]byte("{\"code\":\"signing_failed\",\"message\":\"Signing failed\"}\n"), suffix...)
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		valid := true
		for {
			var value any
			err := decoder.Decode(&value)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				valid = false
				break
			}
		}
		p := &probeTB{TB: t}
		r := New(p)
		write(t, r, "out", data)
		r.ExpectJSON("out", nil, signingFields(), 1)
		if r.Check() && !valid {
			t.Fatal("malformed stream accepted")
		}
		p.finish()
	})
}
