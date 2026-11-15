package tests

import (
	"encoding/csv"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestLeanReferenceVectors(t *testing.T) {
	t.Parallel()
	file, err := os.Open("lean/vectors.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}()
	reader := csv.NewReader(file)
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 10000 {
		t.Fatal("reference vector set is incomplete")
	}
	scanners := map[string]*embargo.Scanner{}
	for _, kind := range []embargo.Kind{embargo.KindPAN, embargo.KindIBAN, embargo.KindMyNumber, embargo.KindEmail} {
		scanners[string(kind)] = embargo.NewScanner(embargo.WithKinds(kind), embargo.WithMinConfidence(0.9))
	}
	number := func(raw string) int {
		n, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for i, row := range rows {
		switch row[0] {
		case "pan", referenceIBANKind, "mynumber":
			got := scanners[row[0]].ScanString(row[1])
			valid := len(got) == 1 && got[0].Start == 0 && got[0].End == len(row[1])
			if valid != (row[2] == "true") {
				t.Fatalf("Lean vector %d (%s) disagrees", i, row[0])
			}
		case "percent":
			got := scanners["email"].ScanString(row[1])
			if len(got) != 1 || got[0].Start != number(row[2]) || got[0].End != number(row[3]) {
				t.Fatalf("Lean position vector %d disagrees", i)
			}
		case "mask":
			spans := []embargo.Finding{{Kind: embargo.KindEmail, Start: number(row[2]), End: number(row[3]), Confidence: 1}, {Kind: embargo.KindPAN, Start: number(row[4]), End: number(row[5]), Confidence: 1}}
			got := embargo.MaskFunc(row[1], spans, func(_ embargo.Kind, part string) string { return strings.Repeat("*", len(part)) })
			if got != row[6] {
				t.Fatalf("Lean union vector %d disagrees", i)
			}
		default:
			t.Fatal("unknown reference vector")
		}
	}
}
