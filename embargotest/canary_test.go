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
	"testing"
)

func TestCanaryRepresentations(t *testing.T) {
	t.Parallel()
	raw := []byte("fake-\"<&\nsecret-0123456789")
	//nolint:errchkjson // Keep marshal errors explicit under errcheck if serialized types evolve.
	j, err := json.Marshal(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	q := strconv.QuoteToASCII(string(raw))
	forms := make([]string, 0, 11)
	forms = append(forms, string(raw), hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)), string(j[1:len(j)-1]), q[1:len(q)-1], fmt.Sprintf("%v", raw), new(big.Int).SetBytes(raw).String())
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		forms = append(forms, encoding.EncodeToString(raw))
	}
	for _, form := range forms {
		if !containsCanary([]byte("prefix "+form+" suffix"), representations(raw)) {
			t.Fatal("canary representation missed")
		}
	}
	if containsCanary(bytes.Repeat([]byte("x"), 200), representations(raw)) {
		t.Fatal("unrelated output detected")
	}
}
