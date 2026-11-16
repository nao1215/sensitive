package main

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

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
		embargo.KindHighEntropy:     {{"unlabeled", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL", .3}},
		embargo.KindCredential:      {{"assignment", "password=synthetic", .95}, {"dsn", "postgres://alice:synthetic@localhost/db", .95}},
		embargo.KindPAN:             {{"Luhn", "4111111111111111", 1}, {"checksum failure", "4111111111111112", .6}, {businessLabelCase, "order_id=4111111111111111", .4}},
		embargo.KindEmail:           {{"known TLD", "alice@example.com", 1}, {"unknown TLD", "alice@example.zzzz", .8}, {"known TLD doubled dot", "alice@ex..ample.com", .9}, {"unknown TLD doubled dot", "alice@ex..ample.zzzz", .7}},
		embargo.KindJPPhone:         {{"mobile", "09012345678", .9}, {"landline", "0312345678", .8}, {businessLabelCase, "order_id=09012345678", .4}},
		embargo.KindMyNumber:        {{checksumCase, "123456789018", .95}, {businessLabelCase, "order_id=123456789018", .4}},
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
		embargo.KindUSSSN:           {{structureCase, "663271262", .6}, {businessLabelCase, "order_id=663271262", .4}},
		embargo.KindUSITIN:          {{structureCase, "984735739", .6}, {businessLabelCase, "order_id=984735739", .4}},
		embargo.KindUKNINO:          {{structureCase, "ZM888570B", .7}, {businessLabelCase, "order_id=ZM888570B", .4}},
		embargo.KindUKNHS:           {{checksumCase, "7694617519", .95}, {businessLabelCase, "order_id=7694617519", .4}},
		embargo.KindIndiaAadhaar:    {{checksumCase, "258726398415", .95}, {businessLabelCase, "order_id=258726398415", .4}},
		embargo.KindIndiaPAN:        {{structureCase, "ATTJE9054P", .7}, {businessLabelCase, "order_id=ATTJE9054P", .4}},
		embargo.KindBrazilCPF:       {{checksumCase, "86017494961", .95}, {businessLabelCase, "order_id=86017494961", .4}},
		embargo.KindBrazilCNPJ:      {{"numeric", "40771605520366", .95}, {"alphanumeric", "12.ABC.345/01DE-35", .95}, {businessLabelCase, "order_id=40771605520366", .4}},
		embargo.KindChinaResidentID: {{checksumCase, "510104199602017742", .95}, {businessLabelCase, "order_id=510104199602017742", .4}},
		embargo.KindKoreaRRN:        {{"legacy", "2203292878073", .95}, {"modern labeled", "rrn=2203292878074", .6}, {businessLabelCase, "order_id=2203292878073", .4}},
		embargo.KindCanadaSIN:       {{"Luhn", "413643081", .95}, {businessLabelCase, "order_id=413643081", .4}},
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
					threshold := embargo.NewScanner(embargo.WithKinds(kind), embargo.WithMinConfidence(tc.score))
					if got := threshold.ScanString(tc.input); len(got) != 1 || embargo.Mask(tc.input, got) == tc.input {
						t.Fatalf("documented inclusive threshold %.17g rejected score %.17g", tc.score, findings[0].Confidence)
					}
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

func TestReadmeDefaults(t *testing.T) {
	t.Parallel()
	if err := checkDefaults(repositoryKinds(t), repositoryReadme(t)); err != nil {
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
					return fmt.Errorf("%s README default disagrees with NewScanner: want %s", doc.name, expected)
				}
			}
		}
		if !found {
			return fmt.Errorf("missing default row for %s", doc.name)
		}
	}
	return nil
}

func TestReadmeDefaultsRejectChangedSelection(t *testing.T) {
	t.Parallel()
	readme := strings.Replace(repositoryReadme(t), "| on |", "| off |", 1)
	if err := checkDefaults(repositoryKinds(t), readme); err == nil {
		t.Fatal("default mismatch accepted")
	}
}
