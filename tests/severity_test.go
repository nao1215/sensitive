package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/nao1215/embargo"
)

const criticalTier = "critical"

func TestResidualCountsEveryUnmaskedByte(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		findings []embargo.Finding
		want     []int
	}{
		{"no finding", nil, []int{6, 2}},
		{"partial key", []embargo.Finding{{Start: 2, End: 5}}, []int{3, 2}},
		{"overlap union", []embargo.Finding{{Start: 2, End: 6}, {Start: 4, End: 8}}, []int{0, 2}},
		{"other kind still masks", []embargo.Finding{{Kind: embargo.KindEmail, Start: 0, End: 12}}, []int{0, 0}},
		{"invalid range fails closed", []embargo.Finding{{Start: -1, End: 2}}, []int{0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := residualBytes([]byte("xxabcdefxxYZ"), tc.findings, []accuracySpan{{Start: 2, End: 8}, {Start: 10, End: 12}})
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCriticalGateRejectsPartialMaskAndRecallLoss(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		tp, fn, bytes int
		want          bool
	}{
		{"complete", 100, 0, 0, true}, {"missed", 99, 1, 0, false}, {"partial", 100, 0, 1, false}, {"empty corpus", 0, 0, 0, false},
	} {
		if got := criticalGate(accuracyCount{tp: tc.tp, fn: tc.fn}, tc.bytes); got != tc.want {
			t.Fatal(tc.name)
		}
	}
}

// residualBytes uses an independent byte bitmap, including Mask's fail-closed range policy.
func residualBytes(text []byte, findings []embargo.Finding, expected []accuracySpan) []int {
	remaining := make([]int, len(expected))
	masked := make([]bool, len(text))
	for _, f := range findings {
		if f.Start < 0 || f.End <= f.Start || f.End > len(text) {
			return remaining
		}
		for i := f.Start; i < f.End; i++ {
			masked[i] = true
		}
	}
	for index, span := range expected {
		for i := span.Start; i < span.End; i++ {
			if !masked[i] {
				remaining[index]++
			}
		}
	}
	return remaining
}

// Both committed critical corpora had 100% exact-span recall at threshold zero before this gate.
func criticalGate(count accuracyCount, residual int) bool {
	return count.tp > 0 && count.fn == 0 && residual == 0
}

func severity(kind embargo.Kind) string {
	switch kind {
	case embargo.KindCredential, embargo.KindServiceToken, embargo.KindAWSKey, embargo.KindGitHubToken, embargo.KindGoogleAPIKey, embargo.KindSlackToken, embargo.KindPaymentToken, embargo.KindPrivateKeyPEM, embargo.KindPAN, embargo.KindJWT:
		return criticalTier
	case embargo.KindUSSSN, embargo.KindUSITIN, embargo.KindUKNINO, embargo.KindUKNHS, embargo.KindIndiaAadhaar, embargo.KindIndiaPAN, embargo.KindBrazilCPF, embargo.KindBrazilCNPJ, embargo.KindChinaResidentID, embargo.KindKoreaRRN, embargo.KindCanadaSIN, embargo.KindMyNumber, embargo.KindBankAccount, embargo.KindIBAN, embargo.KindABARouting, embargo.KindUKSortCode:
		return "high"
	case embargo.KindHighEntropy, embargo.KindEmail, embargo.KindPhone, embargo.KindJPPhone, embargo.KindUSPhone, embargo.KindIPAddr, embargo.KindSWIFTBIC, embargo.KindCVV, embargo.KindCardExpiry, embargo.KindACHTrace, embargo.KindMerchantID, embargo.KindBTC, embargo.KindETH:
		return "standard"
	default:
		panic("evaluation tier missing for kind")
	}
}

type severityResult struct {
	Set            string  `json:"set"`
	Tier           string  `json:"tier"`
	Threshold      float64 `json:"threshold"`
	TP             int     `json:"tp"`
	FP             int     `json:"fp"`
	FN             int     `json:"fn"`
	ExposedSecrets int     `json:"exposed_secrets"`
	ResidualBytes  int     `json:"residual_bytes"`
}

type secretExposure struct {
	Set           string       `json:"set"`
	ID            string       `json:"id"`
	Kind          embargo.Kind `json:"kind"`
	Start         int          `json:"start"`
	End           int          `json:"end"`
	UnmaskedBytes int          `json:"unmasked_bytes"`
}

func TestSeverityAccuracy(t *testing.T) {
	t.Parallel()
	results := make([]severityResult, 0, 18)
	var exposures []secretExposure
	for _, set := range []string{developmentAccuracySet, heldAccuracySet} {
		samples := allAccuracySamples(t, set)
		credentials := readGeneratedAccuracy[labeledAccuracySample](t, "testdata/credentials-"+set+".jsonl")
		for i := range credentials {
			credentials[i].ID = "credentials/" + credentials[i].ID
		}
		samples = append(samples, credentials...)
		samples = append(samples, countrySamples(t, set)...)
		for _, threshold := range []float64{0, .5, .7} {
			scanners := map[embargo.Kind]*embargo.Scanner{}
			counts := map[string]severityResult{}
			for _, sample := range samples {
				tier := severity(sample.Kind)
				findings := accuracyScanner(scanners, sample.Kind, threshold).ScanString(sample.Text)
				score := scoreAccuracy(sample.Kind, findings, sample.Expected)
				count := counts[tier]
				count.Set = set
				count.Threshold = threshold
				count.Tier = tier
				count.TP += score.tp
				count.FP += score.fp
				count.FN += score.fn
				for index, unmasked := range residualBytes([]byte(sample.Text), findings, sample.Expected) {
					if unmasked > 0 {
						count.ExposedSecrets++
					}
					count.ResidualBytes += unmasked
					if threshold == 0 {
						exposures = append(exposures, secretExposure{Set: set, ID: sample.ID, Kind: sample.Kind, Start: sample.Expected[index].Start, End: sample.Expected[index].End, UnmaskedBytes: unmasked})
					}
				}
				counts[tier] = count
			}
			for _, tier := range []string{criticalTier, "high", "standard"} {
				count := counts[tier]
				results = append(results, count)
				if threshold == 0 && tier == criticalTier && !criticalGate(accuracyCount{tp: count.TP, fn: count.FN}, count.ResidualBytes) {
					t.Errorf("%s critical: %d hits, %d misses, %d exposed bytes", set, count.TP, count.FN, count.ResidualBytes)
				}
			}
		}
	}
	syncSeverityJSON(t, "../doc/severity.json", results)
	syncSeverityJSON(t, "testdata/residual-exposure.json", exposures)
}

func syncSeverityJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if os.Getenv("UPDATE_DOCS") == "1" {
		if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		return
	}
	// #nosec G304 -- Callers use fixed repository snapshot paths.
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(actual, []byte("\r\n"), []byte("\n")), data) {
		t.Fatalf("%s differs; run make accuracy-doc", path)
	}
}
