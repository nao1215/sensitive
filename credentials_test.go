package embargo_test

import (
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

//nolint:goconst // Keep each input and expected secret span together.
func TestCredentialSecretSpans(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ text, secret string }{
		{`password=forgotten-pass host=db.example database=orders`, "forgotten-pass"},
		{`{"apiKey":"a forgotten value","count":17}`, "a forgotten value"},
		{`Authorization: Bearer pretend-bearer-token`, "pretend-bearer-token"},
		{`Authorization: Basic ZmFrZTpmaWN0aXRpb3Vz`, "ZmFrZTpmaWN0aXRpb3Vz"},
		{`Cookie: session=forgotten; theme=dark`, "session=forgotten; theme=dark"},
		{`postgres://reader:fake%2Fpass%40word@db.example/orders?sslmode=require`, "fake%2Fpass%40word"},
		{`mysql://reader:forgotten@db.example/orders`, "forgotten"},
		{`reader:forgotten@tcp(db.example:3306)/orders`, "forgotten"},
		{`mongodb+srv://reader:forgotten@db.example/orders`, "forgotten"},
		{`redis://:forgotten@db.example/0`, "forgotten"},
		{`amqp://reader:forgotten@mq.example/vhost`, "forgotten"},
		{`https://bucket.example/file?X-Amz-Signature=pretend-signature&expires=17`, "pretend-signature"},
		{`https://blob.example/file?sig=pretend%2Bsignature%3D&sv=2025`, "pretend%2Bsignature%3D"},
		{`AccountName=demo;AccountKey=pretend-storage-key==;EndpointSuffix=core.windows.net`, "pretend-storage-key=="},
		{`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"}`, `-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n`},
		{`aws_secret_access_key=pretend-key`, "pretend-key"},
		{`TWILIO_AUTH_TOKEN=pretend-auth-token`, "pretend-auth-token"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
			got := scanner.ScanString(tc.text)
			start := strings.Index(tc.text, tc.secret)
			if len(got) != 1 || got[0].Start != start || got[0].End != start+len(tc.secret) {
				t.Fatalf("got %v, want secret span [%d,%d)", got, start, start+len(tc.secret))
			}
			if masked := embargo.Mask(tc.text, got); masked != strings.Replace(tc.text, tc.secret, "[REDACTED]", 1) {
				t.Fatal(masked)
			}
		})
	}
}

func TestCredentialNegatives(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
	for _, text := range []string{"passwordless=true", "token_count=17", "https://example.com/db", "reader@db.example", "password=", `password="[REDACTED]"`, `sigaction=normal`, `classification:public`} {
		if got := scanner.ScanString(text); len(got) != 0 {
			t.Errorf("%q: %v", text, got)
		}
	}
}

func TestCredentialEscapesAndCloudBodies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ text, secret string }{
		{`api key = "forgotten"`, "forgotten"},
		{`AKIAIOSFODNN7EXAMPLE q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUgQx2A9cF6`, "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUgQx2A9cF6"},
		{"-----BEGIN PRIVATE KEY-----\nFAKE-KEY-BODY\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\nFAKE-KEY-BODY\n-----END PRIVATE KEY-----"},
	} {
		scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential, embargo.KindPrivateKeyPEM))
		masked := embargo.Mask(tc.text, scanner.ScanString(tc.text))
		if strings.Contains(masked, tc.secret) {
			t.Errorf("secret retained for %q", tc.text)
		}
	}
}

func TestCredentialMaskingIsIdempotent(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
	for _, text := range []string{"postgres://reader:forgotten@db.example/orders", "password=forgotten", "Authorization: Bearer forgotten"} {
		masked := embargo.Mask(text, scanner.ScanString(text))
		if len(scanner.ScanString(masked)) != 0 {
			t.Fatal("marker detected as a credential")
		}
	}
}

func TestCredentialAssignmentDelimiters(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
	for _, text := range []string{"failure (password=opaque)", "fields [token=opaque]", "record <secret=opaque>", `{"Authorization":"Bearer opaque"}`} {
		got := embargo.Mask(text, scanner.ScanString(text))
		if want := strings.Replace(text, "opaque", "[REDACTED]", 1); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}

func TestCredentialAWSContextDoesNotDuplicateAssignment(t *testing.T) {
	t.Parallel()
	value := "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUgQx2A9cF6"
	text := "AKIAIOSFODNN7EXAMPLE aws_secret_access_key=" + value
	got := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential)).ScanString(text)
	if len(got) != 1 || text[got[0].Start:got[0].End] != value {
		t.Fatalf("expected one credential span, got %v", got)
	}
}
