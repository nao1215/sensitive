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
	text := "alice@example.com ssn 663-27-1262"

	// National IDs are opt-in; WithAll adds them and KindHighEntropy.
	for _, scanner := range []*embargo.Scanner{embargo.NewScanner(), embargo.NewScanner(embargo.WithAll())} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// [REDACTED] ssn 663-27-1262
	// [REDACTED] ssn [REDACTED]
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

func ExampleWithMaskFunc() {
	next := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	lastFour := func(kind embargo.Kind, value string) string {
		if kind != embargo.KindPAN {
			return "[" + strings.ToUpper(string(kind)) + "]"
		}
		return "****" + value[len(value)-4:]
	}
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN), embargo.WithMaskFunc(lastFour))
	logger := slog.New(embargo.NewSlogHandler(next, scanner))

	logger.Info("checkout", "email", "alice@example.com", "card", "4532015112830366", "password", "hunter2")

	// Output: {"level":"INFO","msg":"checkout","email":"[EMAIL]","card":"****0366","password":"[REDACTED]"}
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
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN))

	for _, text := range []string{
		"card 4111111111111111", // Passes the Luhn check.
		"card 4111111111111112", // Fails it, so it is not a card number.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// card [REDACTED]
	// card 4111111111111112
}

func ExampleKindEmail() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))

	for _, text := range []string{
		"mail alice@example.com",
		"mail alice@localhost", // No dotted domain.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// mail [REDACTED]
	// mail alice@localhost
}

func ExampleKindJPPhone() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindJPPhone))

	for _, text := range []string{
		"tel 090-1234-5678",
		"tel +81 90-1234-5678",
		"tel 1234-5678", // Too short for a Japanese number.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// tel [REDACTED]
	// tel [REDACTED]
	// tel 1234-5678
}

func ExampleKindMyNumber() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindMyNumber))

	for _, text := range []string{
		"my_number=123456789018", // The check digit matches.
		"my_number=123456789019", // It does not.
		"order_id=123456789018",  // A record identifier label excludes it.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// my_number=[REDACTED]
	// my_number=123456789019
	// order_id=123456789018
}

func ExampleKindJWT() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindJWT))

	for _, text := range []string{
		"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
		"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0", // Only one dot.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// token [REDACTED]
	// token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0
}

func ExampleKindAWSKey() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindAWSKey))

	for _, text := range []string{
		"key AKIAIOSFODNN7EXAMPLE",
		"key AKIAIOSFODNN7EXAMP", // Too short.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// key [REDACTED]
	// key AKIAIOSFODNN7EXAMP
}

func ExampleKindIBAN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindIBAN))

	for _, text := range []string{
		"iban GB82 WEST 1234 5698 7654 32",
		"iban GB83 WEST 1234 5698 7654 32", // The MOD 97 check fails.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// iban [REDACTED]
	// iban GB83 WEST 1234 5698 7654 32
}

func ExampleKindIPAddr() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindIPAddr))

	for _, text := range []string{
		"client 203.0.113.7",
		"client 2001:db8::1",
		"version 1.2.3.4", // A version label excludes it.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// client [REDACTED]
	// client [REDACTED]
	// version 1.2.3.4
}

func ExampleKindSWIFTBIC() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindSWIFTBIC))

	for _, text := range []string{
		"bic DEUTDEFF500",
		"bic DEUTZZFF", // ZZ is not a country code.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// bic [REDACTED]
	// bic DEUTZZFF
}

func ExampleKindABARouting() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindABARouting))

	for _, text := range []string{
		"routing 021000021", // The 3-7-1 checksum passes.
		"routing 021000022", // It fails.
		"user_id=021000021", // A record identifier label excludes it.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// routing [REDACTED]
	// routing 021000022
	// user_id=021000021
}

func ExampleKindUKSortCode() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUKSortCode))

	for _, text := range []string{
		"sort code 12-34-56",
		"sort code 12-34 56", // Separators differ.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// sort code [REDACTED]
	// sort code 12-34 56
}

func ExampleKindCVV() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCVV))

	for _, text := range []string{
		"cvv: 123",
		"code 123", // No verification-code keyword.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// cvv: [REDACTED]
	// code 123
}

func ExampleKindCardExpiry() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCardExpiry))

	for _, text := range []string{
		"expires 12/29",
		"expires 13/29", // No month 13.
		"shipped 12/29", // No expiry keyword.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// expires [REDACTED]
	// expires 13/29
	// shipped 12/29
}

func ExampleKindPaymentToken() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPaymentToken))

	for _, text := range []string{
		"stripe sk_test_" + strings.Repeat("Fake0", 5),
		"paypal PAYID-" + strings.Repeat("FAKE", 6),
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// stripe [REDACTED]
	// paypal [REDACTED]
}

func ExampleKindBankAccount() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindBankAccount))

	for _, text := range []string{
		"account number 12345678",
		"12345678", // No banking keyword.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// account number [REDACTED]
	// 12345678
}

func ExampleKindACHTrace() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindACHTrace))

	for _, text := range []string{
		"trace number 021000021234567",
		"021000021234567", // No ACH or trace keyword.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// trace number [REDACTED]
	// 021000021234567
}

func ExampleKindMerchantID() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindMerchantID))

	for _, text := range []string{
		"merchant id 123456789012345",
		"terminal id 12345678",
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// merchant id [REDACTED]
	// terminal id [REDACTED]
}

func ExampleKindBTC() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindBTC))

	for _, text := range []string{
		"pay 1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
		"pay bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
		"pay 1BoatSLRHtKNngkdXEeobR76b53LETtpyU", // The Base58Check checksum fails.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// pay [REDACTED]
	// pay [REDACTED]
	// pay 1BoatSLRHtKNngkdXEeobR76b53LETtpyU
}

func ExampleKindETH() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindETH))

	for _, text := range []string{
		"to 0x52908400098527886E0F7030069857D2E4169EE7", // Mixed case passes EIP-55.
		"to 0x52908400098527886e0f7030069857d2e4169ee7", // Uniform case has no checksum.
		"to 0x52908400098527886e0F7030069857D2E4169EE7", // Mixed case fails EIP-55.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// to [REDACTED]
	// to [REDACTED]
	// to 0x52908400098527886e0F7030069857D2E4169EE7
}

func ExampleKindGitHubToken() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindGitHubToken))

	for _, text := range []string{
		"token ghp_" + strings.Repeat("Fake0", 7) + "X", // 36 characters after ghp_.
		"token ghp_" + strings.Repeat("Fake0", 7),       // 35.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// token [REDACTED]
	// token ghp_Fake0Fake0Fake0Fake0Fake0Fake0Fake0
}

func ExampleKindSlackToken() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindSlackToken))

	for _, text := range []string{
		"slack xoxb-0000000000-fake",
		"slack xoxb-short", // Body under 10 characters.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// slack [REDACTED]
	// slack xoxb-short
}

func ExampleKindGoogleAPIKey() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindGoogleAPIKey))

	for _, text := range []string{
		"key AIza" + strings.Repeat("Fake0", 7), // 35 characters after AIza.
		"key AIza" + strings.Repeat("Fake0", 6), // 30.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// key [REDACTED]
	// key AIzaFake0Fake0Fake0Fake0Fake0Fake0
}

func ExampleKindPrivateKeyPEM() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPrivateKeyPEM))

	for _, text := range []string{
		"-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----\nnext line", // The span runs through the END line.
		"-----BEGIN PUBLIC KEY-----", // Not a private key.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// [REDACTED]
	// next line
	// -----BEGIN PUBLIC KEY-----
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

func ExampleNewSlogHandler_quickStart() {
	next := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})

	// README:begin

	// next is the handler you already use, such as slog.NewJSONHandler(os.Stdout, nil).
	logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner()))

	logger.Info("login failed", "email", "alice@example.com", "password", "hunter2", "request_id", "req-7f3a")
	// README:end

	// Output: {"level":"INFO","msg":"login failed","email":"[REDACTED]","password":"[REDACTED]","request_id":"req-7f3a"}
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
	// /profile?email=[REDACTED]
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
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithSensitiveKeys("recovery_code"))
	safe, err := scanner.MaskJSON([]byte(`{"recoveryCode":"opaque","api-key":"opaque","count":3}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(safe))
	// Output:
	// {"recoveryCode":"[REDACTED]","api-key":"[REDACTED]","count":3}
}

func ExampleWithoutDefaultSensitiveKeys() {
	// This API returns a public pagination cursor named token.
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithoutDefaultSensitiveKeys(), embargo.WithSensitiveKeys("password"))
	safe, err := scanner.MaskJSON([]byte(`{"token":"page-2","password":"opaque"}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(safe))
	// Output:
	// {"token":"page-2","password":"[REDACTED]"}
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

// Access logs usually need the client address for incident response. Leaving
// KindIPAddr out of the selection keeps it while credentials, provider
// tokens, email addresses and cards in the request line are still masked.
func ExampleWithKinds_accessLog() {
	scanner := embargo.NewScanner(embargo.WithKinds(
		embargo.KindCredential, embargo.KindServiceToken, embargo.KindJWT, embargo.KindEmail, embargo.KindPAN,
	))
	line := `203.0.113.7 - - [17/Nov/2026:10:00:00 +0000] "GET /reset?email=alice@example.com&token=sk-proj-Fake0Fake0Fake0Fake0Fake0Fake0 HTTP/1.1" 302 0`
	fmt.Println(embargo.Mask(line, scanner.ScanString(line)))
	// Output: 203.0.113.7 - - [17/Nov/2026:10:00:00 +0000] "GET /reset?email=[REDACTED]&token=[REDACTED] HTTP/1.1" 302 0
}

func ExampleKindPhone() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPhone))

	for _, text := range []string{
		"call +44 20 7946 0958",
		"office +44 (0)20 7946 0958", // The trunk prefix (0) is part of the number.
		"tel:+919876543210",
		"balance +1000000",   // Unseparated and under ten digits: a signed amount.
		"+28 20 7946 0958",   // 28 is not an assigned country calling code.
		"call 020 7946 0958", // Without +, numbers follow one country's rules.
	} {
		fmt.Println(embargo.Mask(text, scanner.ScanString(text)))
	}

	// Output:
	// call [REDACTED]
	// office [REDACTED]
	// tel:[REDACTED]
	// balance +1000000
	// +28 20 7946 0958
	// call 020 7946 0958
}

func ExampleKindUSPhone() {
	text := "contact (202) 555-0123 or 202-555-0145"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUSPhone))
	fmt.Println(embargo.Mask(text, scanner.ScanString(text)))

	// Output: contact [REDACTED] or [REDACTED]
}
