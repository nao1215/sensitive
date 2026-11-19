package embargo

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type hostileValue struct{}

func (hostileValue) String() string { panic("evaluated wrapped value") }

func (hostileValue) GoString() string { panic("evaluated wrapped value") }

func (hostileValue) Format(fmt.State, rune) { panic("evaluated wrapped value") }

func (hostileValue) LogValue() slog.Value { panic("evaluated wrapped value") }

func (hostileValue) MarshalJSON() ([]byte, error) { panic("evaluated wrapped value") }

func (hostileValue) MarshalText() ([]byte, error) { panic("evaluated wrapped value") }

func TestSecret(t *testing.T) {
	t.Parallel()
	var zero Secret[int]
	if zero.Reveal() != 0 {
		t.Fatal("nonzero reveal")
	}
	s := NewSecret(hostileValue{})
	if s.String() != redactionMarker || fmt.Sprintf("%#v", s) != "embargo.Secret[github.com/nao1215/embargo.hostileValue]([REDACTED])" || s.LogValue().String() != redactionMarker {
		t.Fatal("display changed")
	}
	for _, verb := range "vbcdoOqxXUeEfFgGstpT%z" {
		for _, flag := range []string{"", "+", "#", "-", " ", "0", "+#020.8"} {
			output := fmt.Sprintf("%"+flag+string(verb), s)
			want := redactionMarker
			if verb == 'v' && strings.Contains(flag, "#") {
				want = "embargo.Secret[github.com/nao1215/embargo.hostileValue]([REDACTED])"
			}
			if verb != 'p' && verb != 'T' && verb != '%' && output != want {
				t.Fatal("formatter redactionMarker changed")
			}
		}
	}
	j, err := json.Marshal(s)
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

func TestSecretStorageAndXML(t *testing.T) {
	t.Parallel()
	value := NewSecret("fake-private-value")
	field := reflect.TypeOf(value).Field(0)
	if field.IsExported() || field.Type.Kind() != reflect.Pointer {
		t.Fatal("secret must use unexported pointer storage")
	}
	type Envelope struct {
		Attribute Secret[string] `xml:"attribute,attr"`
		Element   Secret[string] `xml:"element"`
	}
	data, err := xml.Marshal(Envelope{Attribute: value, Element: value})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `<Envelope attribute="[REDACTED]"><element>[REDACTED]</element></Envelope>` {
		t.Fatal("XML marker contract changed")
	}
}

func TestSecretPanic(t *testing.T) {
	t.Parallel()
	if os.Getenv("EMBARGO_SECRET_CHILD") == "1" {
		panic(NewSecret("fake-private-value"))
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- The executable is the current test binary, with an exact helper test name and isolated environment.
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestSecretPanic$")
	cmd.Env = []string{"EMBARGO_SECRET_CHILD=1"}
	if root, ok := os.LookupEnv("SystemRoot"); ok {
		cmd.Env = append(cmd.Env, "SystemRoot="+root)
	}
	output, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("panic: [REDACTED]")) || bytes.Contains(output, []byte("fake-private-value")) {
		t.Fatal("panic output violated the redaction contract")
	}
}

func TestNoRetiredMarker(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{".", "embargotest"} {
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			// #nosec G304 -- Paths come from fixed local package globs, not caller input.
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.Contains(string(data), "[embargo"+"ed]") {
				t.Errorf("retired marker in %s", path)
			}
		}
	}
}

func TestSecretDebugType(t *testing.T) {
	t.Parallel()
	password := NewSecret("fake-payment-password")
	for _, format := range []string{"%#v", "%+#v", "%#40.3v"} {
		if got := fmt.Sprintf(format, password); got != "embargo.Secret[string]([REDACTED])" {
			t.Fatalf("%s: %s", format, got)
		}
	}
	if _, ok := any(password).(fmt.GoStringer); ok {
		t.Fatal("Secret implements fmt.GoStringer; Format owns the Go-syntax verb")
	}
	var zero Secret[[]byte]
	if got := fmt.Sprintf("%#v", zero); got != "embargo.Secret[[]uint8]([REDACTED])" {
		t.Fatal(got)
	}
}

type stringOnlyPassword string

//nolint:goconst // The literal is an independent output oracle.
func (stringOnlyPassword) String() string { return "[REDACTED]" }

func TestUnexportedFieldFormatting(t *testing.T) {
	t.Parallel()
	const raw = "fake-payment-password"
	homemade := struct{ password stringOnlyPassword }{password: raw}
	protected := struct{ password Secret[string] }{password: NewSecret(raw)}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(format, protected), raw) {
			t.Fatal("Secret exposed its referent")
		}
	}
	if !strings.Contains(fmt.Sprintf("%v", homemade), raw) {
		t.Fatal("fixture no longer demonstrates fmt bypassing String")
	}
}

type failedFormatState struct{}

func (failedFormatState) Write([]byte) (int, error) { return 0, errors.New("closed formatter") }

func (failedFormatState) Width() (int, bool) { return 0, false }

func (failedFormatState) Precision() (int, bool) { return 0, false }

func (failedFormatState) Flag(int) bool { return true }

func TestSecretDoesNotFallBackWhenFormatterFails(t *testing.T) {
	t.Parallel()
	secret := NewSecret("fake-payment-password")
	secret.Format(failedFormatState{}, 'v')
	if secret.Reveal() != "fake-payment-password" {
		t.Fatal("formatter mutated secret")
	}
}

func TestLargeJSONSnapshot(t *testing.T) {
	t.Parallel()
	// Duplicate keys, exact integers and arrays stay visible
	// in the diff. Inspect their meaning before comparing stored bytes.
	source := `{"header":{"sequence":9007199254740993,"ok":true},"rows":[` + strings.TrimSuffix(strings.Repeat(`{"email":"alice@example.com","password":{"opaque":"fixture-private"},"clean":"public","dup":1,"dup":2},`, 32), ",") + `],"tail":null}`
	output, err := NewScanner(WithAll()).MaskJSON([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(output) || bytes.Contains(output, []byte("alice")) || bytes.Contains(output, []byte("fixture-private")) {
		t.Fatal("snapshot is invalid or contains synthetic secrets")
	}
	if bytes.Count(output, []byte(`"dup":1,"dup":2`)) != 32 || !bytes.Contains(output, []byte("9007199254740993")) || bytes.Count(output, []byte(`"clean":"public"`)) != 32 {
		t.Fatal("snapshot lost clean data or duplicate fields")
	}
	var formatted bytes.Buffer
	if err = json.Indent(&formatted, output, "", "  "); err != nil {
		t.Fatal(err)
	}
	if err = formatted.WriteByte('\n'); err != nil {
		t.Fatal(err)
	}
	const path = "testdata/large-json.golden"
	if os.Getenv("UPDATE_SNAPSHOTS") == "1" {
		if err = os.WriteFile(path, formatted.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, formatted.Bytes()) {
		t.Fatal("large JSON snapshot changed; review field structure")
	}
}

// reachableStrings walks v the way method-free printers such as go-spew do:
// through fields, elements and pointers, without calling String or GoString.
func reachableStrings(v reflect.Value, seen map[uintptr]bool, out *[]string) {
	kind := v.Kind()
	if kind == reflect.String {
		*out = append(*out, v.String())
	}
	if (kind == reflect.Pointer || kind == reflect.Interface) && !v.IsNil() {
		if kind == reflect.Pointer && seen[v.Pointer()] {
			return
		}
		if kind == reflect.Pointer {
			seen[v.Pointer()] = true
		}
		reachableStrings(v.Elem(), seen, out)
	}
	if kind == reflect.Struct {
		for _, field := range v.Fields() {
			reachableStrings(field, seen, out)
		}
	}
	if kind == reflect.Slice || kind == reflect.Array {
		for i := range v.Len() {
			reachableStrings(v.Index(i), seen, out)
		}
	}
}

func TestSecretIsUnreachableByReflection(t *testing.T) {
	t.Parallel()
	type config struct {
		Key  Secret[string]
		List Secret[[]string]
		Name string
	}
	c := config{Name: "public", Key: NewSecret("raw-secret-value"), List: NewSecret([]string{"raw-secret-item"})}
	var got []string
	reachableStrings(reflect.ValueOf(c), map[uintptr]bool{}, &got)
	if want := []string{"public"}; !slices.Equal(got, want) {
		t.Fatalf("reflection reached %q, want %q", got, want)
	}
	if c.Key.Reveal() != "raw-secret-value" || c.List.Reveal()[0] != "raw-secret-item" {
		t.Fatal("Reveal lost the wrapped value")
	}
	if same := c.Key; same != c.Key || NewSecret("raw-secret-value") == c.Key {
		t.Fatal("Secret comparison changed: copies compare equal, separate wraps do not")
	}
}
