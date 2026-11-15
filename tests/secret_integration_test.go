package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"text/template"

	"pgregory.net/rapid"

	"github.com/nao1215/embargo"
)

//nolint:gocognit // Exercise the complete type, encoder and formatting cross-product under one shrinker.
func TestSecretProperties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		raw := append([]byte("fake-property-canary-"), rapid.SliceOfN(rapid.Byte(), 16, 100).Draw(t, "secret")...)
		text := string(raw)
		secret := embargo.NewSecret(text)
		var input embargo.Input[string]
		if err := input.UnmarshalText(raw); err != nil {
			t.Fatal("input failed")
		}
		var binary embargo.Input[[]byte]
		if err := binary.UnmarshalText(raw); err != nil {
			t.Fatal("byte input failed")
		}
		bytesSecret := embargo.NewSecret(raw)
		var array [32]byte
		copy(array[:], raw)
		arraySecret := embargo.NewSecret(array)
		forms := []any{
			secret, &secret, input, &input, binary, &binary, bytesSecret, arraySecret,
			struct{ Public embargo.Secret[string] }{secret},
			struct{ private embargo.Secret[string] }{secret},
			[]any{secret},
			map[string]any{"token": input},
			struct{ embargo.Secret[string] }{secret},
			struct{ private embargo.Input[string] }{input},
			fmt.Errorf("wrapped display: %v", secret),
		}
		flags := rapid.SampledFrom([]string{"", "+", "#", "-", " ", "0", "+#020.12", "-# 30.4"}).Draw(t, "flags")
		needles := make([]string, 0, 11)
		needles = append(needles, text, hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)), base64.StdEncoding.EncodeToString(raw), fmt.Sprintf("%v", raw), string(array[:]), hex.EncodeToString(array[:]), strings.ToUpper(hex.EncodeToString(array[:])), base64.StdEncoding.EncodeToString(array[:]), fmt.Sprintf("%v", array))
		escaped, err := json.Marshal(text)
		if err != nil {
			t.Fatal("fixture encoding failed")
		}
		needles = append(needles, string(escaped[1:len(escaped)-1]))
		check := func(output string) {
			for _, needle := range needles {
				if strings.Contains(output, needle) {
					t.Fatal("secret representation found")
				}
			}
		}
		for _, form := range forms {
			for _, verb := range "vbcdoOqxXUeEfFgGstpT%z" {
				check(fmt.Sprintf("%"+flags+string(verb), form))
			}
			j, err := json.Marshal(form)
			if err != nil {
				t.Fatal("JSON encoding failed")
			}
			check(string(j))
			for _, jsonHandler := range []bool{false, true} {
				var out bytes.Buffer
				var handler slog.Handler = slog.NewTextHandler(&out, nil)
				if jsonHandler {
					handler = slog.NewJSONHandler(&out, nil)
				}
				slog.New(handler).With("attached", form).WithGroup("group").Info("event", "value", form)
				check(out.String())
			}
		}
		for _, form := range []any{secret, input} {
			encoded, err := xml.Marshal(struct {
				Value   any      `xml:"value"`
				XMLName xml.Name `xml:"record"`
			}{Value: form})
			if err != nil {
				t.Fatal("XML encoding failed")
			}
			check(string(encoded))
			tpl, err := template.New("value").Parse("{{.}}")
			if err != nil {
				t.Fatal("template parse failed")
			}
			var out bytes.Buffer
			if err := tpl.Execute(&out, form); err != nil {
				t.Fatal("template failed")
			}
			check(out.String())
		}
	})
}

//nolint:goconst // Each formatting combination has an independent literal oracle.
func TestFmtDifferential(t *testing.T) {
	t.Parallel()
	s := embargo.NewSecret("fake-differential-canary")
	var input embargo.Input[string]
	if err := input.UnmarshalText([]byte("fake-differential-canary")); err != nil {
		t.Fatal(err)
	}
	const flags = "+#- 0"
	for mask := range 1 << len(flags) {
		var selected strings.Builder
		for i := range len(flags) {
			if mask&(1<<i) != 0 {
				if _, err := selected.WriteString(string(flags[i])); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, width := range []string{"", "20.8"} {
			for _, verb := range "vbcdoOqxXUeEfFgGstz" {
				format := "%" + selected.String() + width + string(verb)
				want := "[REDACTED]"
				if verb == 'v' && strings.Contains(selected.String(), "#") {
					want = "embargo.Secret[string]([REDACTED])"
				}
				if fmt.Sprintf(format, s) != want || fmt.Sprintf(format, input) != "[REDACTED]" {
					t.Fatal("differential marker mismatch")
				}
			}
		}
	}
}

func TestConcurrentCoreReads(t *testing.T) {
	t.Parallel()
	s := embargo.NewSecret([32]byte{1, 2, 3})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 200 {
				if s.Reveal()[0] != 1 {
					t.Error("copy changed")
				}
				if s.String() != "[REDACTED]" {
					t.Error("display changed")
				}
			}
		})
	}
	wg.Wait()
}
