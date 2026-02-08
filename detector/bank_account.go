package detector

// BankAccountLanguage represents the language of the context keyword that
// triggered a bank account detection.
type BankAccountLanguage string

const (
	// BankAccountLangJA indicates a Japanese context keyword (e.g., "口座番号").
	BankAccountLangJA BankAccountLanguage = "ja"
	// BankAccountLangEN indicates an English context keyword (e.g., "bank account").
	BankAccountLangEN BankAccountLanguage = "en"
)

// BankAccountDetail holds bank account context detection detail information.
type BankAccountDetail struct {
	// ContextKeyword is the keyword that triggered the detection
	// (e.g., "口座番号", "bank account").
	ContextKeyword string
	// Language indicates whether the context keyword was Japanese or English.
	Language BankAccountLanguage
}

// BankAccount detects bank account numbers mentioned near context keywords in text.
//
// This is a context-based weak detector (弱検出). Bank account numbers have no
// universal format or checksum, so detection relies on the presence of banking
// keywords nearby. The confidence is intentionally low (0.5-0.65) to reflect
// the uncertainty.
//
// Detection logic:
//  1. Scan for context keywords:
//     Japanese: "口座番号", "口座名義", "振込先", "銀行口座", "預金口座"
//     English: "bank account", "account number", "acct no", "account no"
//  2. Within a 50-byte radius of each keyword, look for digit sequences
//     of 4-17 digits (covering US, UK, EU, and Japanese account number lengths)
//  3. If a "名義" (holder name) keyword also appears within 50 bytes of the
//     digit sequence, increase confidence to 0.65
//
// Full-width digits (e.g., 口座番号 １２３４５６７８) are normalized to
// half-width before digit extraction, so Japanese text using full-width
// numbers is correctly detected.
//
// Confidence:
//   - 0.50: keyword + digit sequence found
//   - 0.65: keyword + digit sequence + holder name context
type BankAccount struct{}

// NewBankAccount creates a new bank account context detector.
func NewBankAccount() *BankAccount {
	return &BankAccount{}
}

// Name returns "bank_account".
func (d *BankAccount) Name() DetectorName {
	return NameBankAccount
}

// Hints returns byte sequences for pre-filtering.
// These keywords must appear in the input for bank account detection to trigger.
//
// ASCII hints are matched case-insensitively by Scanner's hint filter, so a
// single lowercase entry covers all case variants. Non-ASCII hints (Japanese)
// are matched byte-for-byte.
func (d *BankAccount) Hints() [][]byte {
	return [][]byte{
		// Japanese keywords (UTF-8 encoded).
		// 口座 (account)
		{0xE5, 0x8F, 0xA3, 0xE5, 0xBA, 0xA7},
		// 振込先 (transfer destination)
		{0xE6, 0x8C, 0xAF, 0xE8, 0xBE, 0xBC, 0xE5, 0x85, 0x88},
		// 銀行 (bank)
		{0xE9, 0x8A, 0x80, 0xE8, 0xA1, 0x8C},
		// 預金 (deposit)
		{0xE9, 0xA0, 0x90, 0xE9, 0x87, 0x91},
		// English keywords (one lowercase entry per keyword; case-insensitive
		// matching covers all variants).
		[]byte("bank account"),
		[]byte("account number"),
		[]byte("acct no"),
		[]byte("account no"),
	}
}

// Scan examines data for bank account numbers near context keywords and returns findings.
// Full-width digits are normalized to half-width before digit extraction.
func (d *BankAccount) Scan(data []byte) []Finding {
	normalized, posMap := NormalizeFullWidthDigits(data)
	return d.scanNormalized(data, normalized, posMap)
}

// scanNormalized performs bank account detection on normalized data.
// orig is the original (possibly full-width) input used for RawValue.
func (d *BankAccount) scanNormalized(orig []byte, data []byte, posMap []int) []Finding {
	matches := findKeywordPositions(data, bankAccountKeywords)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding
	used := make(map[int]struct{}) // track digit sequence start positions already reported

	for _, m := range matches {
		// Determine the language of the matched keyword.
		// Keywords are not affected by digit normalization, so data[m.start:m.end]
		// contains the same bytes as the original.
		lang := bankAccountKeywordLang(data[m.start:m.end])

		// Search for digit sequences near the keyword in normalized data.
		seqs := extractDigitsNear(data, m.end, 50, 4, 17)
		for _, seq := range seqs {
			if _, ok := used[seq.start]; ok {
				continue
			}

			// Ensure the digit sequence doesn't overlap with the keyword.
			if seq.start < m.end && seq.end > m.start {
				continue
			}

			used[seq.start] = struct{}{}

			confidence := 0.50
			// Check for holder name keywords near this specific digit sequence
			// (within 50 bytes), not anywhere in the entire input.
			if containsAnyNear(data, seq.start, seq.end, 50, holderNameKeywords) {
				confidence = 0.65
			}

			origStart, origEnd := mapOriginalRange(posMap, seq.start, seq.end)

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        origStart,
				End:          origEnd,
				Confidence:   confidence,
				RawValue:     string(orig[origStart:origEnd]),
				Detail: &BankAccountDetail{
					ContextKeyword: string(data[m.start:m.end]),
					Language:       lang,
				},
			})
		}
	}

	return findings
}

// bankAccountKeywordLang determines the language of a bank account keyword.
func bankAccountKeywordLang(kw []byte) BankAccountLanguage {
	// Japanese keywords are multi-byte UTF-8 (first byte >= 0x80).
	if len(kw) > 0 && kw[0] >= 0x80 {
		return BankAccountLangJA
	}
	return BankAccountLangEN
}

// containsAny reports whether data contains any of the given byte sequences.
func containsAny(data []byte, keywords [][]byte) bool {
	for _, kw := range keywords {
		if containsBytes(data, kw) {
			return true
		}
	}
	return false
}

// containsAnyNear reports whether any of the given byte sequences appear
// within the specified radius of the byte range [regionStart, regionEnd).
// This enables proximity-based keyword matching instead of whole-input scanning.
func containsAnyNear(data []byte, regionStart, regionEnd, radius int, keywords [][]byte) bool {
	start := regionStart - radius
	if start < 0 {
		start = 0
	}
	end := regionEnd + radius
	if end > len(data) {
		end = len(data)
	}
	region := data[start:end]
	for _, kw := range keywords {
		if containsBytes(region, kw) {
			return true
		}
	}
	return false
}

// containsBytes is a simple bytes.Contains implementation to avoid importing bytes
// in this file (it's already imported in context.go where bytes is used).
func containsBytes(data, sub []byte) bool {
	if len(sub) == 0 {
		return true
	}
	if len(sub) > len(data) {
		return false
	}
	for i := 0; i <= len(data)-len(sub); i++ {
		match := true
		for j := range sub {
			if data[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// bankAccountKeywords are the context keywords for bank account detection.
var bankAccountKeywords = [][]byte{
	// Japanese keywords.
	// 口座番号 (account number)
	{0xE5, 0x8F, 0xA3, 0xE5, 0xBA, 0xA7, 0xE7, 0x95, 0xAA, 0xE5, 0x8F, 0xB7},
	// 口座名義 (account holder name)
	{0xE5, 0x8F, 0xA3, 0xE5, 0xBA, 0xA7, 0xE5, 0x90, 0x8D, 0xE7, 0xBE, 0xA9},
	// 振込先 (transfer destination)
	{0xE6, 0x8C, 0xAF, 0xE8, 0xBE, 0xBC, 0xE5, 0x85, 0x88},
	// 銀行口座 (bank account)
	{0xE9, 0x8A, 0x80, 0xE8, 0xA1, 0x8C, 0xE5, 0x8F, 0xA3, 0xE5, 0xBA, 0xA7},
	// 預金口座 (deposit account)
	{0xE9, 0xA0, 0x90, 0xE9, 0x87, 0x91, 0xE5, 0x8F, 0xA3, 0xE5, 0xBA, 0xA7},

	// English keywords (longer first).
	// Common mixed-case variants are included to reduce false negatives
	// from case variations in real-world documents.
	[]byte("bank account"),
	[]byte("Bank Account"),
	[]byte("Bank account"),
	[]byte("BANK ACCOUNT"),
	[]byte("account number"),
	[]byte("Account Number"),
	[]byte("Account number"),
	[]byte("ACCOUNT NUMBER"),
	[]byte("acct no"),
	[]byte("Acct No"),
	[]byte("Acct no"),
	[]byte("ACCT NO"),
	[]byte("account no"),
	[]byte("Account No"),
	[]byte("Account no"),
	[]byte("ACCOUNT NO"),
}

// holderNameKeywords are keywords indicating holder/beneficiary name context.
// Their presence near a bank account number increases confidence.
var holderNameKeywords = [][]byte{
	// 名義 (holder name)
	{0xE5, 0x90, 0x8D, 0xE7, 0xBE, 0xA9},
	// 名義人 (account holder)
	{0xE5, 0x90, 0x8D, 0xE7, 0xBE, 0xA9, 0xE4, 0xBA, 0xBA},
	[]byte("holder"),
	[]byte("Holder"),
	[]byte("beneficiary"),
	[]byte("Beneficiary"),
}
