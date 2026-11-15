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

	fmt.Println(embargo.Mask(text, scanner.ScanString(text)))

	// Output: email=[REDACTED] card=[REDACTED]
}

func ExampleNewScanner() {
	text := "alice@example.com 192.0.2.1 cvv: 123"

	fmt.Println(len(embargo.NewScanner().ScanString(text)))

	fmt.Println(len(embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)).ScanString(text)))

	// Output:
	// 4
	// 1
}

func ExampleScanner() {
	var scanner embargo.Scanner

	fmt.Println(len(scanner.ScanString("alice@example.com")))

	// Output: 1
}

func ExampleScanner_Scan() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))
	for _, f := range scanner.Scan([]byte("card=4111111111111111")) {
		fmt.Println(f.Kind, f.Start, f.End)
	}

	// Output: pan 5 21
}

func ExampleScanner_ScanString() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))

	fmt.Println(len(scanner.ScanString("alice@example.com")))

	// Output: 1
}

func ExampleScanner_ScanLines() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	err := scanner.ScanLines(strings.NewReader("safe\nalice@example.com\n"), func(n int, line []byte, findings []embargo.Finding) {
		fmt.Println(n, embargo.Mask(string(line), findings))
	})
	if err != nil {
		panic(err)
	}

	// Output: 2 [REDACTED]
}

func ExampleScannerOption() {
	options := []embargo.ScannerOption{embargo.WithKinds(embargo.KindEmail), embargo.WithMinConfidence(.9)}

	fmt.Println(len(embargo.NewScanner(options...).ScanString("alice@example.com")))

	// Output: 1
}

func ExampleWithKinds() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))

	fmt.Println(len(scanner.ScanString("alice@example.com 192.0.2.1")))

	// Output: 1
}

func ExampleWithAll() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithAll())

	fmt.Println(len(scanner.ScanString("alice@example.com 192.0.2.1 cvv: 123")))

	// Output: 4
}

func ExampleWithMinConfidence() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindBankAccount), embargo.WithMinConfidence(.9))

	fmt.Println(len(scanner.ScanString("bank account 12345678")))

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

	fmt.Println(embargo.Mask(text, scanner.ScanString(text)))

	// Output: token=[REDACTED]
}

func ExampleDetector() {
	var detector embargo.Detector = projectToken{}

	fmt.Println(len(detector.Scan([]byte("fake_project_token"))))

	// Output: 1
}

func ExampleDetector_Scan() {
	var detector embargo.Detector = projectToken{}
	for _, f := range detector.Scan([]byte("fake_project_token")) {
		fmt.Println(f.Kind)
	}

	// Output: project_token
}

func ExampleKind() {
	kind := embargo.Kind("project_token")

	fmt.Println(kind)

	// Output: project_token
}

func ExampleFinding() {
	text := "card=4111111111111111"
	finding := embargo.Finding{Kind: embargo.KindPAN, Start: 5, End: 21, Confidence: 1}

	fmt.Println(finding.Kind, finding.Start, finding.End, finding.Confidence)

	fmt.Println(embargo.Mask(text, []embargo.Finding{finding}))

	// Output:
	// pan 5 21 1
	// card=[REDACTED]
}

func ExampleMask() {
	text := "email=alice@example.com"

	fmt.Println(embargo.Mask(text, embargo.NewScanner().ScanString(text)))

	// Output: email=[REDACTED]
}

func ExampleMaskFunc() {
	text := "card=4111111111111111"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))
	masked := embargo.MaskFunc(text, scanner.ScanString(text), func(_ embargo.Kind, value string) string { return "[REDACTED]" + value[len(value)-4:] })

	fmt.Println(masked)

	// Output: card=[REDACTED]1111
}

func ExampleKindPAN() {
	fmt.Println(embargo.KindPAN)

	// Output: pan
}

func ExampleKindEmail() {
	fmt.Println(embargo.KindEmail)

	// Output: email
}

func ExampleKindJPPhone() {
	fmt.Println(embargo.KindJPPhone)

	// Output: phone_jp
}

func ExampleKindMyNumber() {
	fmt.Println(embargo.KindMyNumber)

	// Output: mynumber
}

func ExampleKindJWT() {
	fmt.Println(embargo.KindJWT)

	// Output: jwt
}

func ExampleKindAWSKey() {
	fmt.Println(embargo.KindAWSKey)

	// Output: awskey
}

func ExampleKindIBAN() {
	fmt.Println(embargo.KindIBAN)

	// Output: iban
}

func ExampleKindIPAddr() {
	fmt.Println(embargo.KindIPAddr)

	// Output: ipaddr
}

func ExampleKindSWIFTBIC() {
	fmt.Println(embargo.KindSWIFTBIC)

	// Output: swiftbic
}

func ExampleKindABARouting() {
	fmt.Println(embargo.KindABARouting)

	// Output: aba_routing
}

func ExampleKindUKSortCode() {
	fmt.Println(embargo.KindUKSortCode)

	// Output: uk_sortcode
}

func ExampleKindCVV() {
	fmt.Println(embargo.KindCVV)

	// Output: cvv
}

func ExampleKindCardExpiry() {
	fmt.Println(embargo.KindCardExpiry)

	// Output: card_expiry
}

func ExampleKindPaymentToken() {
	fmt.Println(embargo.KindPaymentToken)

	// Output: payment_token
}

func ExampleKindBankAccount() {
	fmt.Println(embargo.KindBankAccount)

	// Output: bank_account
}

func ExampleKindACHTrace() {
	fmt.Println(embargo.KindACHTrace)

	// Output: ach_trace
}

func ExampleKindMerchantID() {
	fmt.Println(embargo.KindMerchantID)

	// Output: merchant_id
}

func ExampleKindBTC() {
	fmt.Println(embargo.KindBTC)

	// Output: btc
}

func ExampleKindETH() {
	fmt.Println(embargo.KindETH)

	// Output: eth
}

func ExampleKindGitHubToken() {
	fmt.Println(embargo.KindGitHubToken)

	// Output: github_token
}

func ExampleKindSlackToken() {
	fmt.Println(embargo.KindSlackToken)

	// Output: slack_token
}

func ExampleKindGoogleAPIKey() {
	fmt.Println(embargo.KindGoogleAPIKey)

	// Output: google_api_key
}

func ExampleKindPrivateKeyPEM() {
	fmt.Println(embargo.KindPrivateKeyPEM)

	// Output: private_key_pem
}
