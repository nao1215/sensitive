package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func repositoryKinds(t *testing.T) []kindDoc {
	t.Helper()
	kinds, err := readKinds("../../../finding.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 39 {
		t.Fatalf("got %d kinds, want 39", len(kinds))
	}
	return kinds
}

func repositoryPage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(pagePath("../../.."))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

const unlabeledCase = "unlabeled"

func TestKindGodocValidation(t *testing.T) {
	t.Parallel()
	for _, kind := range repositoryKinds(t) {
		t.Run(kind.name, func(t *testing.T) {
			t.Parallel()
			if _, err := defaultSetting(kind); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPageKinds(t *testing.T) {
	t.Parallel()
	block, err := detectorBlock(repositoryPage(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range repositoryKinds(t) {
		if strings.Count(block, "["+kind.name+"]") != 1 {
			t.Errorf("%s must have exactly one Kinds page row", kind.name)
		}
	}
	if got := strings.Count(block, "\n| [Kind"); got != len(repositoryKinds(t)) {
		t.Fatalf("unexpected Kinds page rows: %d", got)
	}
}

func TestPageFreshness(t *testing.T) {
	t.Parallel()
	if err := update("../../..", true); err != nil {
		t.Fatal(err)
	}
}

func TestKindGodocRejectsMissingValidation(t *testing.T) {
	t.Parallel()
	for _, doc := range []string{"", "KindFake selects values.", "KindFake matches digits; reports candidates (NewScanner default: on)."} {
		if _, err := defaultSetting(kindDoc{name: "KindFake", doc: doc}); err == nil {
			t.Errorf("accepted incomplete contract %q", doc)
		}
	}
}

func TestPageCheckRejectsStaleBlock(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source, err := os.ReadFile("../../../finding.go")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G703 -- The path is confined to this test temporary directory.
	if err = os.WriteFile(filepath.Join(root, "finding.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(pagePath(root)), 0o700); err != nil {
		t.Fatal(err)
	}
	// #nosec G703 -- The path is confined to this test temporary directory.
	if err = os.WriteFile(pagePath(root), []byte(startMarker+"\nstale\n"+endMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = update(root, false); err != nil {
		t.Fatal(err)
	}
	if err = update(root, true); err != nil {
		t.Fatal(err)
	}
	path := pagePath(root)
	// #nosec G304 -- Read only the temporary page created above.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "| on |", "| off |", 1))
	// #nosec G703 -- The path is confined to this test temporary directory.
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = update(root, true); err == nil {
		t.Fatal("accepted stale page default")
	}
}

type scoreCase struct {
	name, input string
	score       float64
}

// Fixtures exercise every documented score through the public scanner, including
// failure and context branches. These are public examples or synthetic values.
const (
	businessLabelCase = "business label"
	checksumCase      = "checksum"
	contextCase       = "context"
	structureCase     = "structure"
)

func scoreCases() map[embargo.Kind][]scoreCase {
	return map[embargo.Kind][]scoreCase{
		embargo.KindServiceToken:    {{"provider", "sk-proj-abcdefghijklmnop", .95}, {"webhook", "https://hooks.slack.com/services/T0/B0/abcdefghijklmnop", .95}},
		embargo.KindHighEntropy:     {{unlabeledCase, "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL", .3}},
		embargo.KindCredential:      {{"assignment", "password=synthetic", .95}, {"dsn", "postgres://alice:synthetic@localhost/db", .95}},
		embargo.KindPAN:             {{"Luhn", "4111111111111111", 1}, {businessLabelCase, "order_id=4111111111111111", .4}},
		embargo.KindEmail:           {{"known TLD", "alice@example.com", 1}, {"unknown TLD", "alice@example.zzzz", .8}, {"known TLD doubled dot", "alice@ex..ample.com", .9}, {"unknown TLD doubled dot", "alice@ex..ample.zzzz", .7}},
		embargo.KindJPPhone:         {{"mobile", "09012345678", .9}, {"landline", "0312345678", .8}, {businessLabelCase, "order_id=09012345678", .4}},
		embargo.KindUSPhone:         {{unlabeledCase, "202-555-0123", .7}, {"phone label", "phone: (202) 555-0123", .9}, {businessLabelCase, "order_id=202-555-0123", .4}},
		embargo.KindPhone:           {{unlabeledCase, "+44 20 7946 0958", .8}, {"phone label", "phone: +44 20 7946 0958", .9}, {businessLabelCase, "order_id=+44 20 7946 0958", .4}},
		embargo.KindMyNumber:        {{checksumCase, "123456789018", .95}, {"My Number label", "My Number: 123456789018", .95}},
		embargo.KindJWT:             {{"invalid unsigned header", "eyJ.e30.", .5}, {"invalid signed header", "eyJ.e30.sig", .7}, {"unsigned object", "eyJ4IjoxfQ.e30.", .7}, {"signed object", "eyJ4IjoxfQ.e30.sig", .9}, {"unsigned alg", "eyJhbGciOiJub25lIn0.e30.", .8}, {"signed alg", "eyJhbGciOiJIUzI1NiJ9.e30.sig", 1}},
		embargo.KindAWSKey:          {{"access key ID", "AKIAIOSFODNN7EXAMPLE", .95}},
		embargo.KindIBAN:            {{"MOD 97", "DE89370400440532013000", .95}},
		embargo.KindIPAddr:          {{"IPv4", "192.0.2.1", .8}, {"IPv6", "2001:db8::1", .8}},
		embargo.KindSWIFTBIC:        {{"contextual letters", "swift DEUTDEFF", .85}, {"digits", "NWBKGB2L", .85}},
		embargo.KindABARouting:      {{checksumCase, "021000021", .85}},
		embargo.KindUKSortCode:      {{"nondate", "12-34-56", .7}, {"contextual date", "sort code: 20-12-25", .55}},
		embargo.KindCVV:             {{contextCase, "cvv: 123", .85}},
		embargo.KindCardExpiry:      {{contextCase, "exp: 12/25", .85}},
		embargo.KindPaymentToken:    {{"payment", "tok_abcdefgh", .9}},
		embargo.KindBankAccount:     {{contextCase, "bank account 12345678", .5}, {"holder", "account number 12345678 holder John", .65}},
		embargo.KindACHTrace:        {{contextCase, "ACH 021000020000001", .75}},
		embargo.KindMerchantID:      {{"merchant", "MID: ABC123456789012", .7}, {"terminal", "TID: 12345678", .7}},
		embargo.KindBTC:             {{"Base58Check", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", .95}, {"Bech32", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", .95}, {"Bech32m", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", .95}},
		embargo.KindETH:             {{"uniform", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", .8}, {"EIP-55", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", .95}},
		embargo.KindGitHubToken:     {{"classic", "ghp_" + strings.Repeat("a", 36), .95}, {"fine grained", "github_pat_" + strings.Repeat("a", 22), .95}},
		embargo.KindSlackToken:      {{"bot", "xoxb-1234567890", .9}},
		embargo.KindGoogleAPIKey:    {{"key", "AIza" + strings.Repeat("a", 35), .9}},
		embargo.KindPrivateKeyPEM:   {{"header", "-----BEGIN PRIVATE KEY-----", .99}, {"body", "-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END RSA PRIVATE KEY-----", .99}},
		embargo.KindUSSSN:           {{structureCase, "ssn 663271262", .6}},
		embargo.KindUSITIN:          {{structureCase, "itin 984735739", .6}},
		embargo.KindUKNINO:          {{structureCase, "ZM888570B", .7}},
		embargo.KindUKNHS:           {{checksumCase, "nhs 7694617519", .95}},
		embargo.KindIndiaAadhaar:    {{checksumCase, "aadhaar 258726398415", .95}},
		embargo.KindIndiaPAN:        {{structureCase, "ATTJE9054P", .7}},
		embargo.KindBrazilCPF:       {{checksumCase, "86017494961", .95}},
		embargo.KindBrazilCNPJ:      {{"numeric", "40771605520366", .95}, {"alphanumeric", "12.ABC.345/01DE-35", .95}},
		embargo.KindChinaResidentID: {{checksumCase, "510104199602017742", .95}},
		embargo.KindKoreaRRN:        {{"legacy", "2203292878073", .95}, {"modern labeled", "rrn=2203292878074", .6}},
		embargo.KindCanadaSIN:       {{"Luhn", "sin 413643081", .95}},
	}
}

func TestKindConfidenceScores(t *testing.T) {
	t.Parallel()
	fixtures := scoreCases()
	kinds := repositoryKinds(t)
	if len(fixtures) != len(kinds) {
		t.Fatal("score fixtures must cover exactly the Kind inventory")
	}
	for _, doc := range kinds {
		t.Run(doc.name, func(t *testing.T) {
			t.Parallel()
			kind := embargo.Kind(doc.value)
			cases := fixtures[kind]
			if len(cases) == 0 {
				t.Fatal("no representative inputs")
			}
			scanner := embargo.NewScanner(embargo.WithKinds(kind))
			observed := map[string]bool{}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					// Sequential cases accumulate the score set for this one kind.
					findings := scanner.ScanString(tc.input)
					if len(findings) != 1 || findings[0].Kind != kind {
						t.Fatalf("expected one %s finding: %+v", kind, findings)
					}
					if math.Abs(findings[0].Confidence-tc.score) > 1e-12 {
						t.Fatalf("confidence %g, want %g", findings[0].Confidence, tc.score)
					}
					checkScoreThreshold(t, kind, tc, findings[0].Confidence)
					observed[scoreText(findings[0].Confidence)] = true
				})
			}
			documented := map[string]bool{}
			for _, score := range regexp.MustCompile(`\b(?:0\.\d+|1\.0)\b`).FindAllString(doc.doc, -1) {
				value, err := strconv.ParseFloat(score, 64)
				if err != nil {
					t.Fatal(err)
				}
				documented[scoreText(value)] = true
			}
			if !slices.Equal(sortedScores(documented), sortedScores(observed)) {
				t.Fatalf("documented scores %v, scanned scores %v", sortedScores(documented), sortedScores(observed))
			}
		})
	}
}

func scoreText(value float64) string { return strconv.FormatFloat(value, 'f', 12, 64) }

func sortedScores(scores map[string]bool) []string {
	result := make([]string, 0, len(scores))
	for value := range scores {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func TestPageDefaults(t *testing.T) {
	t.Parallel()
	if err := checkDefaults(repositoryKinds(t), repositoryPage(t)); err != nil {
		t.Fatal(err)
	}
}

func checkDefaults(kinds []kindDoc, readme string) error {
	block, err := detectorBlock(readme)
	if err != nil {
		return err
	}
	defaults := embargo.NewScanner()
	fixtures := scoreCases()
	for _, doc := range kinds {
		kind := embargo.Kind(doc.value)
		cases := fixtures[kind]
		if len(cases) == 0 {
			return fmt.Errorf("no input for %s", kind)
		}
		enabled := false
		for _, tc := range cases {
			for _, finding := range defaults.ScanString(tc.input) {
				enabled = enabled || finding.Kind == kind
			}
		}
		expected := "off"
		if enabled {
			expected = "on"
		}
		found := false
		for line := range strings.SplitSeq(block, "\n") {
			if strings.HasPrefix(line, "| ["+doc.name+"]") {
				found = true
				if !strings.HasSuffix(line, "| "+expected+" |") {
					return fmt.Errorf("%s page default disagrees with NewScanner: want %s", doc.name, expected)
				}
			}
		}
		if !found {
			return fmt.Errorf("missing default row for %s", doc.name)
		}
	}
	return nil
}

func TestPageDefaultsRejectChangedSelection(t *testing.T) {
	t.Parallel()
	readme := strings.Replace(repositoryPage(t), "| on |", "| off |", 1)
	if err := checkDefaults(repositoryKinds(t), readme); err == nil {
		t.Fatal("default mismatch accepted")
	}
}

func checkScoreThreshold(t *testing.T, kind embargo.Kind, tc scoreCase, actual float64) {
	t.Helper()
	threshold := embargo.NewScanner(embargo.WithKinds(kind), embargo.WithMinConfidence(tc.score))
	if got := threshold.ScanString(tc.input); len(got) != 1 || embargo.Mask(tc.input, got) == tc.input {
		t.Fatalf("documented inclusive threshold %.17g rejected score %.17g", tc.score, actual)
	}
}
