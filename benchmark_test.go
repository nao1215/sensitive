package sensitive_test

import (
	"testing"

	"github.com/nao1215/sensitive"
)

func BenchmarkScannerNoMatch(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithAll())
	line := []byte(`2024-01-15T10:30:00Z INFO server started on port 8080 request_id=abc123`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithPAN(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithPAN())
	line := []byte(`payment processed for card 4532-0151-1283-0366 amount $99.99`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithEmail(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithEmail())
	line := []byte(`user tanaka@example.com logged in from 192.168.1.1`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithJPPhone(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithJPPhone())
	line := []byte(`call center: 090-1234-5678`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithMyNumber(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithMyNumber())
	line := []byte(`mynumber: 123456789018`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithJWT(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithJWT())
	line := []byte(`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithAWSKey(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithAWSKey())
	line := []byte(`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithIBAN(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithIBAN())
	line := []byte(`IBAN: DE89370400440532013000`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithIPAddr(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithIPAddr())
	line := []byte(`client 2001:db8::1 connected`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithSWIFTBIC(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithSWIFTBIC())
	line := []byte(`SWIFT: DEUTDEFF`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithABARouting(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithABARouting())
	line := []byte(`routing: 021000021`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithUKSortCode(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithUKSortCode())
	line := []byte(`sort code: 12-34-56`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithCVV(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithCVV())
	line := []byte(`CVV 123`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithCardExpiry(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithCardExpiry())
	line := []byte(`exp 12/29`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithPaymentToken(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithPaymentToken())
	line := []byte(`stripe key sk_live_1234567890abcdef`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithBankAccount(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithBankAccount())
	line := []byte(`bank account 12345678`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithACHTrace(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithACHTrace())
	line := []byte(`ACH trace 021000021123456`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerWithMerchantID(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithMerchantID())
	line := []byte(`merchant ID ABCDE12345FGHI6`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerAllDetectors(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithAll())
	line := []byte(`user tanaka@example.com paid with 4532-0151-1283-0366 from 192.168.1.1`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

func BenchmarkScannerEmptyInput(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithAll())
	b.ResetTimer()
	for range b.N {
		scanner.Scan(nil)
	}
}

// BenchmarkScannerLargeInput measures performance on a ~4KB log block
// with no sensitive data. This exercises the hint filter path at scale.
func BenchmarkScannerLargeInput(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithAll())
	line := []byte("2024-01-15T10:30:00Z INFO server started on port 8080 request_id=abc123\n")
	// Repeat to build ~4KB input.
	var buf []byte
	for len(buf) < 4096 {
		buf = append(buf, line...)
	}
	b.ResetTimer()
	for range b.N {
		scanner.Scan(buf)
	}
}

// BenchmarkScannerHintMatchNoDetection measures the worst case where
// hints match (triggering detector execution) but no actual sensitive
// data is found. This exercises every detector's Scan path.
func BenchmarkScannerHintMatchNoDetection(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithAll())
	// Contains "0" (JPPhone/ABA hint), "@" (Email hint), digits (PAN hints),
	// "ACH" (ACHTrace hint), "merchant" (MerchantID hint), etc.
	// but no actual valid sensitive data.
	line := []byte(`0 merchant ACH trace 12345 user@invalid 4999-0000-0000-0000 exp 99/99 CVV 0 TID 0 bank account 0 sort code 00-00-00`)
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}

// BenchmarkScannerFullWidthInput measures performance on full-width
// digit input that requires normalization.
func BenchmarkScannerFullWidthInput(b *testing.B) {
	scanner := sensitive.NewScanner(sensitive.WithAll())
	// Full-width: ０９０－１２３４－５６７８
	line := []byte("\xef\xbc\x90\xef\xbc\x99\xef\xbc\x90\xef\xbc\x8d\xef\xbc\x91\xef\xbc\x92\xef\xbc\x93\xef\xbc\x94\xef\xbc\x8d\xef\xbc\x95\xef\xbc\x96\xef\xbc\x97\xef\xbc\x98")
	b.ResetTimer()
	for range b.N {
		scanner.Scan(line)
	}
}
