package embargo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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

func ExampleNewSlogHandler() {
	next := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		},
	})
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	logger := slog.New(embargo.NewSlogHandler(next, scanner))
	logger.Info("checkout", "email", "alice@example.com", "card", "4532015112830366")

	// Output: level=INFO msg=checkout email=[REDACTED] card=[REDACTED]
}

func ExampleNewSlogHandler_short() {
	next := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})

	// README:begin
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	logger := slog.New(embargo.NewSlogHandler(next, scanner))

	logger.Info("checkout", "email", "alice@example.com")
	// README:end

	// Output: {"level":"INFO","msg":"checkout","email":"[REDACTED]"}
}

func ExampleNewSlogHandler_struct() {
	next := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})

	// README:begin

	// An existing type: no tags, no embargo field types.
	type User struct {
		Name     string
		Email    string
		Password string
	}
	logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner()))

	logger.Info("signup", "user", User{Name: "carol", Email: "carol@example.com", Password: "hunter2"})
	// README:end

	// Output: {"level":"INFO","msg":"signup","user":{"Name":"carol","Email":"[REDACTED]","Password":"[REDACTED]"}}
}

func ExampleKindCredential() {
	// #nosec G101 -- Deliberately fictitious credential for a runnable masking example.
	text := "postgres://reader:forgotten@db.example/orders"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
	fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	// Output: postgres://reader:[REDACTED]@db.example/orders
}

func ExampleKindServiceToken() {
	text := "upstream rejected sk-proj-" + strings.Repeat("Fake0", 8)
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindServiceToken))
	fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	// Output: upstream rejected [REDACTED]
}

func ExampleKindHighEntropy() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindHighEntropy))
	findings := scanner.ScanString("q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg")
	fmt.Println(len(findings), findings[0].Confidence)
	// Output: 1 0.3
}

func ExampleNewHTTPHandler() {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := embargo.NewHTTPHandler(next, logger, embargo.NewScanner())
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/profile?email=alice@example.com", http.NoBody)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var event struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
		panic(err)
	}
	fmt.Println(response.Code)
	fmt.Println(event.Target)
	// Output:
	// 204
	// /profile?email=%5BREDACTED%5D
}

func ExampleScanner_MaskJSON() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	// Sanitize an audit export before uploading it to a support system.
	safe, err := scanner.MaskJSON([]byte(`{"user":{"email":"alice@example.com","password":"opaque"},"amount":125,"paid":true}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(safe))
	// Output:
	// {"user":{"email":"[REDACTED]","password":"[REDACTED]"},"amount":125,"paid":true}
}

func ExampleWithSensitiveKeys() {
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithSensitiveKeys("password", "passwd", "secret", "token", "api_key", "authorization", "cookie", "set-cookie", "recovery_code"))
	safe, err := scanner.MaskJSON([]byte(`{"recoveryCode":"opaque","api-key":"opaque","count":3}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(safe))
	// Output:
	// {"recoveryCode":"[REDACTED]","api-key":"[REDACTED]","count":3}
}

func ExampleInput_Scan() {
	var password embargo.Input[string]
	// rows.Scan(&password) calls the same method with the driver's string or bytes.
	if err := password.Scan([]byte("synthetic-database-password")); err != nil {
		panic(err)
	}
	secret := password.Secret()
	fmt.Println(secret)
	fmt.Println(secret.Reveal() == "synthetic-database-password")
	// Output:
	// [REDACTED]
	// true
}

func ExampleScanner_MaskJSONContext() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	safe, err := embargo.NewScanner().MaskJSONContext(ctx, []byte(`{"email":"alice@example.com"}`))
	fmt.Println(len(safe), err != nil)
	// Output: 0 true
}

func ExampleNewSecret() {
	key := embargo.NewSecret("fake-key")

	fmt.Println(key)

	// Output: [REDACTED]
}

func ExampleSecret() {
	var empty embargo.Secret[string]

	fmt.Println(empty, empty.Reveal() == "")

	// Output: [REDACTED] true
}

func ExampleSecret_Reveal() {
	key := embargo.NewSecret("fake-key")

	fmt.Println(len(key.Reveal()))

	// Output: 8
}

func ExampleInput() {
	var input embargo.Input[string]
	if err := input.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(input)

	// Output: [REDACTED]
}

func ExampleInput_UnmarshalJSON() {
	var config struct {
		Token embargo.Input[string] `json:"token"`
	}
	if err := json.Unmarshal([]byte(`{"token":"fake-key"}`), &config); err != nil {
		panic(err)
	}

	fmt.Println(config.Token.Secret())

	// Output: [REDACTED]
}

func ExampleInput_UnmarshalJSON_failure() {
	var config struct {
		First  embargo.Input[string] `json:"first"`
		Second embargo.Input[string] `json:"second"`
	}
	if err := json.Unmarshal([]byte(`{"first":"fake-key","second":"[REDACTED]"}`), &config); err != nil {
		fmt.Println("configuration rejected")
		return // Discard the whole partially decoded config.
	}
	panic("unexpected successful decode")

	// Output: configuration rejected
}

func ExampleInput_UnmarshalText() {
	var input embargo.Input[[]byte]
	if err := input.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(input.Secret())

	// Output: [REDACTED]
}

func ExampleInput_Secret() {
	var input embargo.Input[string]
	if err := input.UnmarshalText([]byte("first")); err != nil {
		panic(err)
	}
	snapshot := input.Secret()
	if err := input.UnmarshalText([]byte("second")); err != nil {
		panic(err)
	}

	fmt.Println(len(snapshot.Reveal()))

	// Output: 5
}

func ExampleSecret_String() {
	value := embargo.NewSecret("fake-key")

	fmt.Println(value.String())

	// Output: [REDACTED]
}

func ExampleSecret_GoString() {
	value := embargo.NewSecret("fake-key")

	fmt.Println(value.GoString())

	// Output: embargo.Secret[string]([REDACTED])
}

func ExampleSecret_Format() {
	value := embargo.NewSecret("fake-key")

	fmt.Printf("%+#v\n", value)

	// Output: embargo.Secret[string]([REDACTED])
}

func ExampleSecret_LogValue() {
	value := embargo.NewSecret("fake-key")

	fmt.Println(value.LogValue().String())

	// Output: [REDACTED]
}

func ExampleSecret_MarshalJSON() {
	value := embargo.NewSecret("fake-key")
	data, err := value.MarshalJSON()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	// Output: "[REDACTED]"
}

func ExampleSecret_MarshalText() {
	value := embargo.NewSecret("fake-key")
	data, err := value.MarshalText()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	// Output: [REDACTED]
}

func ExampleInput_String() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(value.String())

	// Output: [REDACTED]
}

func ExampleInput_GoString() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(value.GoString())

	// Output: [REDACTED]
}

func ExampleInput_Format() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Printf("%+#v\n", value)

	// Output: [REDACTED]
}

func ExampleInput_LogValue() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}

	fmt.Println(value.LogValue().String())

	// Output: [REDACTED]
}

func ExampleInput_MarshalJSON() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	data, err := value.MarshalJSON()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	// Output: "[REDACTED]"
}

func ExampleInput_MarshalText() {
	var value embargo.Input[string]
	if err := value.UnmarshalText([]byte("fake-key")); err != nil {
		panic(err)
	}
	data, err := value.MarshalText()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	// Output: [REDACTED]
}

func ExampleMask_log() {
	text := "INFO checkout email=alice@example.com card=4111111111111111"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	findings := scanner.ScanString(text)

	fmt.Println(text)
	fmt.Println(embargo.Mask(text, findings))
	fmt.Println(embargo.MaskFunc(text, findings, func(kind embargo.Kind, value string) string {
		if kind == embargo.KindPAN {
			return "[REDACTED]" + value[len(value)-4:]
		}
		return "[REDACTED]"
	}))

	// Output:
	// INFO checkout email=alice@example.com card=4111111111111111
	// INFO checkout email=[REDACTED] card=[REDACTED]
	// INFO checkout email=[REDACTED] card=[REDACTED]1111
}

func ExampleMask_overlap() {
	text := "token=abcdef"
	findings := []embargo.Finding{
		{Kind: "first", Start: 6, End: 10, Confidence: 1},
		{Kind: "second", Start: 8, End: 12, Confidence: 1},
	}

	fmt.Println(text)
	fmt.Println(text[findings[0].Start:findings[0].End], text[findings[1].Start:findings[1].End])
	fmt.Println(embargo.Mask(text, findings))

	// Output:
	// token=abcdef
	// abcd cdef
	// token=[REDACTED]
}

func ExampleKindUSSSN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUSSSN))
	input := "us_ssn=663-27-1262"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: us_ssn=[REDACTED]
}

func ExampleKindUSITIN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUSITIN))
	input := "us_itin=984-73-5739"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: us_itin=[REDACTED]
}

func ExampleKindUKNINO() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUKNINO))
	input := "uk_nino=ZM 88 85 70 B"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: uk_nino=[REDACTED]
}

func ExampleKindUKNHS() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUKNHS))
	input := "uk_nhs=769 461 7519"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: uk_nhs=[REDACTED]
}

func ExampleKindIndiaAadhaar() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindIndiaAadhaar))
	input := "in_aadhaar=2587 2639 8415"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: in_aadhaar=[REDACTED]
}

func ExampleKindIndiaPAN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindIndiaPAN))
	input := "in_pan=ATTJE9054P"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: in_pan=[REDACTED]
}

func ExampleKindBrazilCPF() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindBrazilCPF))
	input := "br_cpf=860.174.949-61"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: br_cpf=[REDACTED]
}

func ExampleKindBrazilCNPJ() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindBrazilCNPJ))
	input := "br_cnpj=40.771.605/5203-66"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: br_cnpj=[REDACTED]
}

func ExampleKindChinaResidentID() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindChinaResidentID))
	input := "cn_resident_id=510104199602017742"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: cn_resident_id=[REDACTED]
}

func ExampleKindKoreaRRN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindKoreaRRN))
	input := "kr_rrn=220329-2878073"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: kr_rrn=[REDACTED]
}

func ExampleKindCanadaSIN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCanadaSIN))
	input := "ca_sin=413-643-081"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: ca_sin=[REDACTED]
}
