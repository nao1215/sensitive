package main

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

// tokenMember is a JSON key line whose value follows on the next line.
const (
	tokenMember = `  "token":`
	nextValue   = `    "next"`
	closeArray  = "  ]"
)

// filtered runs the filter over the lines joined with newlines.
func filtered(t *testing.T, lines ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(nil, strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(out.String(), "\n")
}

func TestStructureMasksValuesWhoseKeyIsOnAnotherLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		input, want []string
	}{
		{"json value on the next line", []string{"{", tokenMember, `    "opaque-value",`, `  "count":`, "    17", "}"}, []string{"{", tokenMember, `    "` + filterMarker + `",`, `  "count":`, "    17", "}"}},
		{"json number under a key-hinted name", []string{"{", `  "cvv":`, "    123", "}"}, []string{"{", `  "cvv":`, "    " + filterMarker, "}"}},
		{"json array and object under a sensitive key", []string{"[", "  {", `    "secret": [`, `      "one",`, "      {", `        "inner": "two", "n": 3`, "      }", "    ],", `    "name": "public"`, "  }", "]"}, []string{"[", "  {", `    "secret": [`, `      "` + filterMarker + `",`, "      {", `        "inner": "` + filterMarker + `", "n": ` + filterMarker, "      }", "    ],", `    "name": "public"`, "  }", "]"}},
		{"json array under a public key", []string{"{", `  "names": [`, `    "public"`, closeArray, "}"}, []string{"{", `  "names": [`, `    "public"`, closeArray, "}"}},
		{"json escapes in a key and a value", []string{"{", `  "password":`, `    "a\"b",`, `  "x": "y"`, "}"}, []string{"{", `  "password":`, `    "` + filterMarker + `",`, `  "x": "y"`, "}"}},
		{"json document ends and text follows", []string{"{", `  "a": 1`, "}", `"token":`, `  "public"`}, []string{"{", `  "a": 1`, "}", `"token":`, "  " + filterMarker}},
		{"text that only looks like json", []string{"[INFO] started", "  value", "[2026-11-20] {", tokenMember, `    "x"`}, []string{"[INFO] started", "  value", "[2026-11-20] {", tokenMember, "    " + filterMarker}},
		{"a string cut at the line end stops the document", []string{"{", `  "note": "open`, tokenMember, nextValue}, []string{"{", `  "note": "open`, tokenMember, "    " + filterMarker}},
		{"a mismatched close stops the document", []string{"{", closeArray, tokenMember, nextValue}, []string{"{", closeArray, tokenMember, "    " + filterMarker}},
		{"a key that is not a string stops the document", []string{"{", "  17: 1", tokenMember, nextValue}, []string{"{", "  17: 1", tokenMember, "    " + filterMarker}},
		{"yaml comment after an item marker", []string{"token:", "  -  # c", "  -  item"}, []string{"token:", "  -  # c", "  -  " + filterMarker}},
		{"cef empty labeled value", []string{`CEF:0|A|B|1|2|n|5|cs1Label=token cs1= cs2=x`}, []string{`CEF:0|A|B|1|2|n|5|cs1Label=token cs1= cs2=x`}},
		{"yaml literal block", []string{"password: |", "  first line", "", "  second line", "user: bob"}, []string{"password: " + filterMarker, "  " + filterMarker, "", "  " + filterMarker, "user: bob"}},
		{"yaml folded block with indicators and a comment", []string{`"api_key": >-2 # note`, "    folded # kept", "next: public"}, []string{`"api_key": ` + filterMarker + " # note", "    " + filterMarker, "next: public"}},
		{"yaml items and continuation under an empty value", []string{"secret:", "  - one # c", "  - nested: public", "  plain words", "  # comment", "done: public"}, []string{"secret:", "  - " + filterMarker + " # c", "  - nested: public", "  " + filterMarker, "  # comment", "done: public"}},
		{"yaml block ends at the key indentation", []string{"  token:", "    - inner", "  other: public", "    - outer"}, []string{"  token:", "    - " + filterMarker, "  other: public", "    - outer"}},
		{"yaml public key opens nothing", []string{"names:", "  - public", "notes: |", "  public text"}, []string{"names:", "  - public", "notes: |", "  public text"}},
		{"cef custom labels", []string{`CEF:0|Acme|App\|x|1.0|100|login|5|suser=alice cs1Label=password cs1=two words cs2Label=note cs2=public cn1Label=cvv cn1=123 cs3=unlabeled`}, []string{`CEF:0|Acme|App\|x|1.0|100|login|5|suser=alice cs1Label=password cs1=` + filterMarker + ` cs2Label=note cs2=public cn1Label=cvv cn1=` + filterMarker + ` cs3=unlabeled`}},
		{"cef with an escaped equals and a cut header", []string{`syslog CEF:0|A|B|1|2|n|5|cs1Label=token cs1=a\=b c=d`, `CEF:0|A|B|1|2|n|cs1Label=token cs1=public`}, []string{`syslog CEF:0|A|B|1|2|n|5|cs1Label=token cs1=` + filterMarker + ` c=d`, `CEF:0|A|B|1|2|n|cs1Label=token cs1=public`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, want := filtered(t, tc.input...), strings.Join(tc.want, "\n"); got != want {
				t.Fatalf("got\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestStructureFindingsAreReported(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	input := "{\n  \"token\":\n    \"opaque\"\n}\n"
	if err := run([]string{flagFormat, formatJSONL}, strings.NewReader(input), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"credential","start":18,"end":24,"line":3,"column":5}` + "\n"; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

func TestStructureKeepsJSONLinesWholeOutsideDocuments(t *testing.T) {
	t.Parallel()
	// A complete JSON line still goes through MaskJSON and is written compact.
	if got := filtered(t, `{ "pass": "x" }`); got != `{"pass":"`+filterMarker+`"}` {
		t.Fatalf("got %q", got)
	}
	// Inside a document, an inner line that is JSON by itself stays as written.
	if got := filtered(t, "[", `  { "n": 1 },`, "]"); got != "[\n  { \"n\": 1 },\n]" {
		t.Fatalf("got %q", got)
	}
}

func TestKeySensitiveRemembersABoundedNumberOfKeys(t *testing.T) {
	t.Parallel()
	s := newStructure(embargo.NewScanner())
	if !s.keySensitive(passwordColumn) || s.keySensitive("status") || !s.keySensitive("pass") {
		t.Fatal("keySensitive disagrees with MaskJSON")
	}
	if !s.keySensitive(filterEmail) {
		t.Fatal("a key that MaskJSON masks must count as sensitive")
	}
	for i := range maxProbedKeys + 10 {
		s.keySensitive("key" + strconv.Itoa(i))
	}
	if len(s.sensitive) != maxProbedKeys {
		t.Fatalf("remembered %d keys, want %d", len(s.sensitive), maxProbedKeys)
	}
	if s.keySensitive(passwordColumn) != true {
		t.Fatal("a remembered key changed")
	}
}

func TestMergeFindingsDropsCoveredExtras(t *testing.T) {
	t.Parallel()
	base := []embargo.Finding{{Kind: embargo.KindEmail, Start: 2, End: 8, Confidence: 1}}
	extra := []embargo.Finding{
		{Kind: embargo.KindCredential, Start: 2, End: 8, Confidence: 1},
		{Kind: embargo.KindCredential, Start: 3, End: 7, Confidence: 1},
		{Kind: embargo.KindCredential, Start: 1, End: 8, Confidence: 1},
		{Kind: embargo.KindCredential, Start: 2, End: 9, Confidence: 1},
	}
	got := mergeFindings(base, extra)
	if len(got) != 3 || got[1].Start != 1 || got[2].End != 9 {
		t.Fatalf("got %v", got)
	}
}

func TestYAMLHelpers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		content string
		key     string
		value   int
		ok      bool
	}{
		{"password: x", "password", 10, true},
		{"password:", "password", 9, true},
		{"'token':  # c", "token", 13, true},
		{"url: http://x", "url", 5, true},
		{"http://x", "", 0, false},
		{": x", "", 0, false},
		{"a b: x", "", 0, false},
		{`"": x`, "", 0, false},
	} {
		key, value, ok := yamlKey([]byte(tc.content))
		if key != tc.key || value != tc.value || ok != tc.ok {
			t.Errorf("yamlKey(%q) = %q, %d, %v", tc.content, key, value, ok)
		}
	}
	for value, want := range map[string]bool{"|": true, ">": true, "|-": true, ">+2": true, "|2-": true, "|0": false, "|--x": false, "x": false, "": false, "|a": false} {
		if blockIndicator([]byte(value)) != want {
			t.Errorf("blockIndicator(%q) != %v", value, want)
		}
	}
}

func TestCEFPairs(t *testing.T) {
	t.Parallel()
	body := []byte(`k1=a b k2=c\ d k3= x=`)
	pairs := cefPairs(body, 0)
	got := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		got = append(got, string(pair.key)+"="+string(body[pair.start:pair.end]))
	}
	if want := []string{"k1=a b", `k2=c\ d`, "k3=", "x="}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
	if pairs := cefPairs([]byte("novalue"), 0); len(pairs) != 0 {
		t.Fatalf("got %v", pairs)
	}
	if unescapedPipe([]byte(`a\|b|c`), 0) != 4 || unescapedPipe([]byte("abc"), 0) != -1 {
		t.Fatal("unescapedPipe")
	}
}
