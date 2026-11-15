package embargo_test

import (
	"bytes"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestSecretStorageAndXML(t *testing.T) {
	t.Parallel()
	value := embargo.NewSecret("fake-private-value")
	field := reflect.TypeOf(value).Field(0)
	if field.IsExported() || field.Type.Kind() != reflect.Pointer {
		t.Fatal("secret must use unexported pointer storage")
	}
	type Envelope struct {
		Attribute embargo.Secret[string] `xml:"attribute,attr"`
		Element   embargo.Secret[string] `xml:"element"`
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
		panic(embargo.NewSecret("fake-private-value"))
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
