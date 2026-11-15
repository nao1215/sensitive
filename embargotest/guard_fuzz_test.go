package embargotest

import (
	"bytes"
	"strconv"
	"testing"
)

func FuzzGuardFraming(f *testing.F) {
	f.Add([]byte("\x16=== RUN   forged-name\npassword=synthetic"), uint16(32), uint16(8))
	f.Add([]byte("=== RUN   fake\n[REDACTED]\n"), uint16(1), uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, limit, split uint16) {
		if len(data) > 65536 {
			t.Skip()
		}
		maxBytes := int64(limit%4096) + 1
		cut := int(split) % (len(data) + 1)
		capture := &guardCapture{maxBytes: maxBytes}
		for index, chunk := range [][]byte{data[:cut], data[cut:]} {
			writer := &guardStream{capture: capture, index: index}
			n, err := writer.Write(chunk)
			if n != len(chunk) || err != nil {
				t.Fatal("flood did not drain")
			}
		}
		if capture.retained != min(int64(len(data)), maxBytes) || capture.overflow != (int64(len(data)) > maxBytes) {
			t.Fatal("shared output budget bypass")
		}
		joined := append(append([]byte{}, capture.data[0]...), capture.data[1]...)
		if !bytes.Equal(joined, data[:len(joined)]) {
			t.Fatal("capture reframed bytes")
		}
		count, err := strconv.Atoi(guardTests(data))
		if err != nil || count < 0 || count > bytes.Count(data, []byte("\n"))+1 {
			t.Fatal("untrusted framing escaped fixed diagnostic")
		}
	})
}
