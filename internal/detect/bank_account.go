package detect

// BankAccount implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindBankAccount.
type BankAccount struct {
	bankAccountKeywords *keywordSet
}

// NewBankAccount finds account-shaped digits near banking labels without assuming a universal checksum.
func NewBankAccount() *BankAccount {
	return &BankAccount{bankAccountKeywords: bankAccountKeywords()}
}

// Name returns "bank_account".
func (d *BankAccount) Name() DetectorName {
	return NameBankAccount
}

// Hints returns the pre-filter substrings for [BankAccount].
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

// Scan returns matches in data using the rules documented on [BankAccount].
func (d *BankAccount) Scan(data []byte) []Finding {
	normalized, posMap := normalizeDigits(data)
	return d.scanNormalized(normalized, posMap)
}

// scanNormalized performs bank account detection on normalized data.
func (d *BankAccount) scanNormalized(data []byte, posMap []int) []Finding {
	matches := d.bankAccountKeywords.findPositions(data)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding
	used := make(map[int]struct{}) // track digit sequence start positions already reported

	for _, m := range matches {
		// Search for digit sequences near the keyword in normalized data.
		//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
		seqs := extractDigitsNear(data, m.end, 50, 4, 17)
		for _, seq := range seqs {
			if _, ok := used[seq.start]; ok {
				continue
			}

			used[seq.start] = struct{}{}

			confidence := 0.50
			// Check for holder name keywords near this specific digit sequence
			// (within 50 bytes), not anywhere in the entire input.
			//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
			if containsAnyNear(data, seq.start, seq.end, 50, holderNameKeywords()) {
				confidence = 0.65
			}

			origStart, origEnd := mapOriginalRange(posMap, seq.start, seq.end)

			findings = append(findings, Finding{
				DetectorName: d.Name(),
				Start:        origStart,
				End:          origEnd,
				Confidence:   confidence,
			})
		}
	}

	return findings
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
	start := max(regionStart-radius, 0)
	end := min(regionEnd+radius, len(data))
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
func bankAccountKeywords() *keywordSet {
	return newKeywordSet([][]byte{
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
	})
}

// holderNameKeywords are keywords indicating holder/beneficiary name context.
// Their presence near a bank account number increases confidence.
func holderNameKeywords() [][]byte {
	return [][]byte{
		// 名義 (holder name)
		{0xE5, 0x90, 0x8D, 0xE7, 0xBE, 0xA9},
		// 名義人 (account holder)
		{0xE5, 0x90, 0x8D, 0xE7, 0xBE, 0xA9, 0xE4, 0xBA, 0xBA},
		[]byte("holder"),
		[]byte("Holder"),
		[]byte("beneficiary"),
		[]byte("Beneficiary"),
	}
}
