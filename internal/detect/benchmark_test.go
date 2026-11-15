package detect_test

import (
	"testing"

	"github.com/nao1215/embargo/internal/detect"
)

// Per-detector benchmarks measure each detector's Scan() cost in isolation,
// bypassing the Scanner's hint filter and dedup stages.

func BenchmarkDetectorPAN(b *testing.B) {
	d := detect.NewPAN()
	data := []byte("payment processed for card 4532-0151-1283-0366 amount $99.99")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorEmail(b *testing.B) {
	d := detect.NewEmail()
	data := []byte("user tanaka@example.com logged in from 192.168.1.1")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorJPPhone(b *testing.B) {
	d := detect.NewJPPhone()
	data := []byte("call center: 090-1234-5678")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorMyNumber(b *testing.B) {
	d := detect.NewMyNumber()
	data := []byte("mynumber: 123456789018")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorJWT(b *testing.B) {
	d := detect.NewJWT()
	data := []byte("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorAWSKey(b *testing.B) {
	d := detect.NewAWSKey()
	data := []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorIBAN(b *testing.B) {
	d := detect.NewIBAN()
	data := []byte("IBAN: DE89370400440532013000")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorIPAddr(b *testing.B) {
	d := detect.NewIPAddr()
	data := []byte("client 2001:db8::1 connected from 192.168.1.100")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorSWIFTBIC(b *testing.B) {
	d := detect.NewSWIFTBIC()
	data := []byte("SWIFT: DEUTDEFF")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorABARouting(b *testing.B) {
	d := detect.NewABARouting()
	data := []byte("routing: 021000021")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorUKSortCode(b *testing.B) {
	d := detect.NewUKSortCode()
	data := []byte("sort code: 12-34-56")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorCVV(b *testing.B) {
	d := detect.NewCVV()
	data := []byte("CVV 123")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorCardExpiry(b *testing.B) {
	d := detect.NewCardExpiry()
	data := []byte("exp 12/29")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorPaymentToken(b *testing.B) {
	d := detect.NewPaymentToken()
	data := []byte("stripe key sk_live_1234567890abcdef")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorBankAccount(b *testing.B) {
	d := detect.NewBankAccount()
	data := []byte("bank account 12345678")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorACHTrace(b *testing.B) {
	d := detect.NewACHTrace()
	data := []byte("ACH trace 021000021123456")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorMerchantID(b *testing.B) {
	d := detect.NewMerchantID()
	data := []byte("merchant ID ABCDE12345FGHI6")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorBTC(b *testing.B) {
	d := detect.NewBTC()
	data := []byte("btc: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

func BenchmarkDetectorETH(b *testing.B) {
	d := detect.NewETH()
	data := []byte("eth: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

// BenchmarkDetectorPAN_NoMatch measures PAN detector cost when no match is found.
func BenchmarkDetectorPAN_NoMatch(b *testing.B) {
	d := detect.NewPAN()
	data := []byte("2024-01-15T10:30:00Z INFO server started on port 8080 request_id=abc123")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

// BenchmarkDetectorPAN_HighDensity measures PAN detector cost with multiple cards.
func BenchmarkDetectorPAN_HighDensity(b *testing.B) {
	d := detect.NewPAN()
	data := []byte("4532015112830366 5425233430109903 378282246310005 3530111333300000 6011111111111117")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}

// BenchmarkDetectorEmail_HighDensity measures Email detector cost with multiple addresses.
func BenchmarkDetectorEmail_HighDensity(b *testing.B) {
	d := detect.NewEmail()
	data := []byte("alice@example.com bob@test.org carol@example.jp dave@example.co.uk eve@test.net")
	b.ResetTimer()
	for range b.N {
		d.Scan(data)
	}
}
