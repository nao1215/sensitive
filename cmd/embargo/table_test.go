package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

// Fixtures shared by the table tests.
const (
	csvFile        = "a.csv"
	passwordColumn = "password"
	dataColumn     = "data"
)

func TestInputModeFollowsTheFlagOrEveryExtension(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		flag, want string
		files      []string
	}{
		{"", inputLines, nil},
		{"", inputCSV, []string{csvFile, "B.CSV.gz", "c.csv.bz2"}},
		{"", inputTSV, []string{"a.tsv"}},
		{"", inputLines, []string{csvFile, "b.tsv"}},
		{"", inputLines, []string{csvFile, "b.log"}},
		{"", inputLines, []string{"a.log", "b.csv"}},
		{"", inputLines, []string{"csv"}},
		{"", inputLines, []string{"a.gz"}},
		{inputCSV, inputCSV, nil},
		{inputLines, inputLines, []string{csvFile}},
	} {
		if got := inputMode(tc.flag, tc.files); got != tc.want {
			t.Errorf("inputMode(%q, %q) = %q, want %q", tc.flag, tc.files, got, tc.want)
		}
	}
}

// tabled runs the filter with --input mode over the lines joined with newlines.
func tabled(t *testing.T, mode string, lines ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run([]string{flagInput, mode}, strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(out.String(), "\n")
}

func TestTableMasksColumnsByTheirNames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, mode  string
		input, want []string
	}{
		{"plain fields", inputCSV, []string{"id,password,cvv,note", "1,hunter2xyz,123,public", "2,,7,"}, []string{"id,password,cvv,note", "1," + filterMarker + "," + filterMarker + ",public", "2,,7,"}},
		{"quoted fields with delimiters and doubled quotes", inputCSV, []string{`"id","pass ""word"" ",token`, `"1,2","a""b",x`, `"3",  "y" ,z`}, []string{`"id","pass ""word"" ",token`, `"1,2","a""b",` + filterMarker, `"3",  "y" ,` + filterMarker}},
		{"a quoted field across lines keeps its column", inputCSV, []string{"note,secret,id", `public,"first`, `second`, `third",7`, "x,y,z"}, []string{"note,secret,id", `public,"` + filterMarker, filterMarker, filterMarker + `",7`, "x," + filterMarker + ",z"}},
		{"a quoted header name across lines", inputCSV, []string{`"a`, `b",password`, "1,x"}, []string{`"a`, `b",password`, "1,x"}},
		{"a quoted field closed at the line end", inputCSV, []string{"secret,id", `"a`, `b"`, "x,1"}, []string{"secret,id", `"` + filterMarker, filterMarker + `"`, filterMarker + ",1"}},
		{"a repeated header starts a new file", inputCSV, []string{passwordColumn, "x", passwordColumn, "y"}, []string{passwordColumn, filterMarker, passwordColumn, filterMarker}},
		{"extra fields and empty names have no key", inputCSV, []string{"id,,", "a,b,c,d"}, []string{"id,,", "a,b,c,d"}},
		{"values are still scanned", inputCSV, []string{"id,note", "1," + filterEmail}, []string{"id,note", "1," + filterMarker}},
		{"json-looking fields stay text", inputCSV, []string{dataColumn, `{ "n": 1 }`}, []string{dataColumn, `{ "n": 1 }`}},
		{"tab separated", inputTSV, []string{"id\ttoken", "1\tabc,def"}, []string{"id\ttoken", "1\t" + filterMarker}},
		{"a byte order mark before the header", inputCSV, []string{utf8BOM + "token,id", "x,1"}, []string{utf8BOM + "token,id", filterMarker + ",1"}},
		{"lines mode ignores the header", inputLines, []string{passwordColumn, "hunter2xyz"}, []string{passwordColumn, "hunter2xyz"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, want := tabled(t, tc.mode, tc.input...), strings.Join(tc.want, "\n"); got != want {
				t.Fatalf("got\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestTableFindingsAreReported(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if err := run([]string{flagFormat, formatJSONL, flagInput, inputCSV}, strings.NewReader("id,token\n1,abc\n"), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"credential","start":11,"end":14,"line":2,"column":2}` + "\n"; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

func TestQuotedEnd(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		body   string
		end    int
		closed bool
	}{
		{`ab"`, 2, true},
		{`a""b"`, 4, true},
		{`a""`, 3, false},
		{`ab`, 2, false},
		{``, 0, false},
		{`"`, 0, true},
	} {
		if end, closed := quotedEnd([]byte(tc.body), 0); end != tc.end || closed != tc.closed {
			t.Errorf("quotedEnd(%q) = %d, %v; want %d, %v", tc.body, end, closed, tc.end, tc.closed)
		}
	}
	lines := newTable(embargo.NewScanner(), ',')
	if lines.findings([]byte("a,b")) != nil || len(lines.header) != 2 {
		t.Fatalf("header %q", lines.header)
	}
}
