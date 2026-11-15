package embargo_test

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/nao1215/embargo"
)

func Example() {
	text := "email=alice@example.com card=4111111111111111"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	if _, err := fmt.Println(embargo.Mask(text, scanner.ScanString(text))); err != nil {
		panic(err)
	}
	// Output: email=[REDACTED] card=[REDACTED]
}

func ExampleNewScanner() {
	text := "alice@example.com 192.0.2.1 cvv: 123"
	if _, err := fmt.Println(len(embargo.NewScanner().ScanString(text))); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(len(embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)).ScanString(text))); err != nil {
		panic(err)
	}
	// Output:
	// 4
	// 1
}

func ExampleScanner() {
	var scanner embargo.Scanner
	if _, err := fmt.Println(len(scanner.ScanString("alice@example.com"))); err != nil {
		panic(err)
	}
	// Output: 1
}

func ExampleScanner_Scan() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))
	for _, f := range scanner.Scan([]byte("card=4111111111111111")) {
		if _, err := fmt.Println(f.Kind, f.Start, f.End); err != nil {
			panic(err)
		}
	}
	// Output: pan 5 21
}

func ExampleScanner_ScanString() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	if _, err := fmt.Println(len(scanner.ScanString("alice@example.com"))); err != nil {
		panic(err)
	}
	// Output: 1
}

func ExampleScanner_ScanLines() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	err := scanner.ScanLines(strings.NewReader("safe\nalice@example.com\n"), func(n int, line []byte, findings []embargo.Finding) {
		if _, err := fmt.Println(n, embargo.Mask(string(line), findings)); err != nil {
			panic(err)
		}
	})
	if err != nil {
		panic(err)
	}
	// Output: 2 [REDACTED]
}

func ExampleScannerOption() {
	options := []embargo.ScannerOption{embargo.WithKinds(embargo.KindEmail), embargo.WithMinConfidence(.9)}
	if _, err := fmt.Println(len(embargo.NewScanner(options...).ScanString("alice@example.com"))); err != nil {
		panic(err)
	}
	// Output: 1
}

func ExampleWithKinds() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	if _, err := fmt.Println(len(scanner.ScanString("alice@example.com 192.0.2.1"))); err != nil {
		panic(err)
	}
	// Output: 1
}

func ExampleWithAll() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithAll())
	if _, err := fmt.Println(len(scanner.ScanString("alice@example.com 192.0.2.1 cvv: 123"))); err != nil {
		panic(err)
	}
	// Output: 4
}

func ExampleWithMinConfidence() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindBankAccount), embargo.WithMinConfidence(.9))
	if _, err := fmt.Println(len(scanner.ScanString("bank account 12345678"))); err != nil {
		panic(err)
	}
	// Output: 0
}

type projectToken struct{}

func (projectToken) Scan(data []byte) []embargo.Finding {
	const token = "fake_project_token"
	start := bytes.Index(data, []byte(token))
	if start < 0 {
		return nil
	}
	return []embargo.Finding{{Kind: "project_token", Start: start, End: start + len(token), Confidence: 1}}
}

func ExampleWithDetector() {
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(projectToken{}))
	text := "token=fake_project_token"
	if _, err := fmt.Println(embargo.Mask(text, scanner.ScanString(text))); err != nil {
		panic(err)
	}
	// Output: token=[REDACTED]
}

func ExampleDetector() {
	var detector embargo.Detector = projectToken{}
	if _, err := fmt.Println(len(detector.Scan([]byte("fake_project_token")))); err != nil {
		panic(err)
	}
	// Output: 1
}

func ExampleDetector_Scan() {
	var detector embargo.Detector = projectToken{}
	for _, f := range detector.Scan([]byte("fake_project_token")) {
		if _, err := fmt.Println(f.Kind); err != nil {
			panic(err)
		}
	}
	// Output: project_token
}

func ExampleKind() {
	kind := embargo.Kind("project_token")
	if _, err := fmt.Println(kind); err != nil {
		panic(err)
	}
	// Output: project_token
}

func ExampleFinding() {
	text := "card=4111111111111111"
	finding := embargo.Finding{Kind: embargo.KindPAN, Start: 5, End: 21, Confidence: 1}
	if _, err := fmt.Println(finding.Kind, finding.Start, finding.End, finding.Confidence); err != nil {
		panic(err)
	}
	if _, err := fmt.Println(embargo.Mask(text, []embargo.Finding{finding})); err != nil {
		panic(err)
	}
	// Output:
	// pan 5 21 1
	// card=[REDACTED]
}

func ExampleMask() {
	text := "email=alice@example.com"
	if _, err := fmt.Println(embargo.Mask(text, embargo.NewScanner().ScanString(text))); err != nil {
		panic(err)
	}
	// Output: email=[REDACTED]
}

func ExampleMaskFunc() {
	text := "card=4111111111111111"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))
	masked := embargo.MaskFunc(text, scanner.ScanString(text), func(_ embargo.Kind, value string) string { return "[REDACTED]" + value[len(value)-4:] })
	if _, err := fmt.Println(masked); err != nil {
		panic(err)
	}
	// Output: card=[REDACTED]1111
}

func ExampleKindPAN() {
	if _, err := fmt.Println(embargo.KindPAN); err != nil {
		panic(err)
	}
	// Output: pan
}

func ExampleKindEmail() {
	if _, err := fmt.Println(embargo.KindEmail); err != nil {
		panic(err)
	}
	// Output: email
}

func ExampleKindJPPhone() {
	if _, err := fmt.Println(embargo.KindJPPhone); err != nil {
		panic(err)
	}
	// Output: phone_jp
}

func ExampleKindMyNumber() {
	if _, err := fmt.Println(embargo.KindMyNumber); err != nil {
		panic(err)
	}
	// Output: mynumber
}

func ExampleKindJWT() {
	if _, err := fmt.Println(embargo.KindJWT); err != nil {
		panic(err)
	}
	// Output: jwt
}

func ExampleKindAWSKey() {
	if _, err := fmt.Println(embargo.KindAWSKey); err != nil {
		panic(err)
	}
	// Output: awskey
}

func ExampleKindIBAN() {
	if _, err := fmt.Println(embargo.KindIBAN); err != nil {
		panic(err)
	}
	// Output: iban
}

func ExampleKindIPAddr() {
	if _, err := fmt.Println(embargo.KindIPAddr); err != nil {
		panic(err)
	}
	// Output: ipaddr
}

func ExampleKindSWIFTBIC() {
	if _, err := fmt.Println(embargo.KindSWIFTBIC); err != nil {
		panic(err)
	}
	// Output: swiftbic
}

func ExampleKindABARouting() {
	if _, err := fmt.Println(embargo.KindABARouting); err != nil {
		panic(err)
	}
	// Output: aba_routing
}

func ExampleKindUKSortCode() {
	if _, err := fmt.Println(embargo.KindUKSortCode); err != nil {
		panic(err)
	}
	// Output: uk_sortcode
}

func ExampleKindCVV() {
	if _, err := fmt.Println(embargo.KindCVV); err != nil {
		panic(err)
	}
	// Output: cvv
}

func ExampleKindCardExpiry() {
	if _, err := fmt.Println(embargo.KindCardExpiry); err != nil {
		panic(err)
	}
	// Output: card_expiry
}

func ExampleKindPaymentToken() {
	if _, err := fmt.Println(embargo.KindPaymentToken); err != nil {
		panic(err)
	}
	// Output: payment_token
}

func ExampleKindBankAccount() {
	if _, err := fmt.Println(embargo.KindBankAccount); err != nil {
		panic(err)
	}
	// Output: bank_account
}

func ExampleKindACHTrace() {
	if _, err := fmt.Println(embargo.KindACHTrace); err != nil {
		panic(err)
	}
	// Output: ach_trace
}

func ExampleKindMerchantID() {
	if _, err := fmt.Println(embargo.KindMerchantID); err != nil {
		panic(err)
	}
	// Output: merchant_id
}

func ExampleKindBTC() {
	if _, err := fmt.Println(embargo.KindBTC); err != nil {
		panic(err)
	}
	// Output: btc
}

func ExampleKindETH() {
	if _, err := fmt.Println(embargo.KindETH); err != nil {
		panic(err)
	}
	// Output: eth
}

func ExampleKindGitHubToken() {
	if _, err := fmt.Println(embargo.KindGitHubToken); err != nil {
		panic(err)
	}
	// Output: github_token
}

func ExampleKindSlackToken() {
	if _, err := fmt.Println(embargo.KindSlackToken); err != nil {
		panic(err)
	}
	// Output: slack_token
}

func ExampleKindGoogleAPIKey() {
	if _, err := fmt.Println(embargo.KindGoogleAPIKey); err != nil {
		panic(err)
	}
	// Output: google_api_key
}

func ExampleKindPrivateKeyPEM() {
	if _, err := fmt.Println(embargo.KindPrivateKeyPEM); err != nil {
		panic(err)
	}
	// Output: private_key_pem
}
