package embargo_test

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestCountryDefinitionCorpus(t *testing.T) {
	t.Parallel()
	file, err := os.Open("tests/testdata/countries-development.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewScanner(file)
	scanners := map[embargo.Kind]*embargo.Scanner{}
	for reader.Scan() {
		var row struct {
			ID       string       `json:"id"`
			Kind     embargo.Kind `json:"kind"`
			Text     string       `json:"text"`
			Expected []struct {
				Start int `json:"start"`
				End   int `json:"end"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(reader.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		// Public identifiers have valid syntax; their false positives are measured separately.
		if strings.Contains(row.ID, "/public-id/") {
			continue
		}
		scanner := scanners[row.Kind]
		if scanner == nil {
			scanner = embargo.NewScanner(embargo.WithKinds(row.Kind))
			scanners[row.Kind] = scanner
		}
		got := scanner.ScanString(row.Text)
		if len(got) != len(row.Expected) || (len(row.Expected) > 0 && (got[0].Start != row.Expected[0].Start || got[0].End != row.Expected[0].End)) {
			t.Errorf("%s: got %v, want %v", row.ID, got, row.Expected)
		}
	}
	if err := reader.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestCountryStructureRejections(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind  embargo.Kind
		value string
	}{
		{embargo.KindUSSSN, "000123456"},
		{embargo.KindUSSSN, "666123456"},
		{embargo.KindUSSSN, "900123456"},
		{embargo.KindUSSSN, "123004567"},
		{embargo.KindUSSSN, "123450000"},
		{embargo.KindUSITIN, "912491234"},
		{embargo.KindUSITIN, "912661234"},
		{embargo.KindUSITIN, "912891234"},
		{embargo.KindUSITIN, "912931234"},
		{embargo.KindUKNINO, "DD123456A"},
		{embargo.KindUKNINO, "AO123456A"},
		{embargo.KindUKNINO, "BG123456A"},
		{embargo.KindUKNINO, "AB123456E"},
		{embargo.KindUKNHS, "0000000000"},
		{embargo.KindUKNHS, "1000000010"},
		{embargo.KindBrazilCPF, "00000000000"},
		{embargo.KindBrazilCNPJ, "00000000000000"},
		{embargo.KindBrazilCNPJ, "12.abc.345/01DE-35"},
		{embargo.KindChinaResidentID, "11010120230230001X"},
		{embargo.KindChinaResidentID, "000101199001010010"},
		{embargo.KindChinaResidentID, "110101199001010000"},
		{embargo.KindKoreaRRN, "rrn=9902311000000"},
		{embargo.KindKoreaRRN, "rrn=0001015000000"},
	} {
		if got := embargo.NewScanner(embargo.WithKinds(tc.kind)).ScanString(tc.value); len(got) != 0 {
			t.Errorf("%s accepted %s: %v", tc.kind, tc.value, got)
		}
	}
}

func TestCountryRRNEighteenthCenturyAndFullWidth(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"rrn=0001019000000", "rrn=0001010000000"} {
		if got := embargo.NewScanner(embargo.WithKinds(embargo.KindKoreaRRN)).ScanString(value); len(got) != 1 {
			t.Fatal("explicit historical RRN structure missed")
		}
	}
	value := "記録 １２３-４５６-７８２ 完了"
	got := embargo.NewScanner(embargo.WithKinds(embargo.KindCanadaSIN)).ScanString(value)
	if len(got) != 1 || value[got[0].Start:got[0].End] != "１２３-４５６-７８２" {
		t.Fatal(got)
	}
}
