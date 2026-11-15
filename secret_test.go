package embargo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
)

type hostileValue struct{}

func (hostileValue) String() string               { panic("evaluated wrapped value") }
func (hostileValue) GoString() string             { panic("evaluated wrapped value") }
func (hostileValue) Format(fmt.State, rune)       { panic("evaluated wrapped value") }
func (hostileValue) LogValue() slog.Value         { panic("evaluated wrapped value") }
func (hostileValue) MarshalJSON() ([]byte, error) { panic("evaluated wrapped value") }
func (hostileValue) MarshalText() ([]byte, error) { panic("evaluated wrapped value") }

func TestSecret(t *testing.T) {
	t.Parallel()
	var zero Secret[int]
	if zero.Reveal() != 0 {
		t.Fatal("nonzero reveal")
	}
	s := NewSecret(hostileValue{})
	if s.String() != redactionMarker || s.GoString() != redactionMarker || s.LogValue().String() != redactionMarker {
		t.Fatal("display changed")
	}
	for _, verb := range "vbcdoOqxXUeEfFgGstpT%z" {
		for _, flag := range []string{"", "+", "#", "-", " ", "0", "+#020.8"} {
			output := fmt.Sprintf("%"+flag+string(verb), s)
			if verb != 'p' && verb != 'T' && verb != '%' && output != redactionMarker {
				t.Fatal("formatter redactionMarker changed")
			}
		}
	}
	j, err := json.Marshal(s)
	//nolint:goconst // Keep expected marker and error strings independent of production constants.
	if err != nil || string(j) != `"[REDACTED]"` {
		t.Fatal("JSON changed")
	}
	b, err := s.MarshalText()
	if err != nil || string(b) != redactionMarker {
		t.Fatal("text changed")
	}
	var buffer bytes.Buffer
	slog.New(slog.NewTextHandler(&buffer, nil)).Info("event", "secret", s)
	if !bytes.Contains(buffer.Bytes(), []byte(redactionMarker)) {
		t.Fatal("slog redactionMarker absent")
	}
}

func TestSecretShallowCopy(t *testing.T) {
	t.Parallel()
	a := [2]int{1, 2}
	s := NewSecret(a)
	a[0] = 3
	if s.Reveal()[0] != 1 {
		t.Fatal("array not copied")
	}
	b := []int{1}
	p := NewSecret(b)
	b[0] = 2
	if p.Reveal()[0] != 2 {
		t.Fatal("slice should share referent")
	}
}
