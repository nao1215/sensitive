package detect

import "github.com/nao1215/embargo/internal/ascii"

// BankAccount implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindBankAccount.
type BankAccount struct {
	holders [][]byte
	rule    nearRule
}

// NewBankAccount finds account-shaped digits near banking labels without assuming a universal checksum.
func NewBankAccount() *BankAccount {
	d := &BankAccount{holders: holderNameKeywords()}
	//nolint:mnd // Literal field widths follow the format rules documented on this detector.
	d.rule = nearRule{keywords: bankAccountKeywords(), class: ascii.IsDigit, accept: d.confidence, radius: 50, minLen: 4, maxLen: 17}
	return d
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
	return d.rule.scan(nil, d.Name(), data, posMap)
}

// confidence raises the score when holder context appears within 50
// bytes of this digit sequence, not anywhere in the input.
func (d *BankAccount) confidence(data []byte, seq digitSequence) (float64, bool) {
	//nolint:mnd // The radius and scores are documented on this detector.
	if containsNear(data, seq.start, seq.end, 50, d.holders) {
		return 0.65, true
	}
	//nolint:mnd // The score is documented on this detector.
	return 0.50, true
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

		// English keywords; keywordSet folds ASCII case.
		[]byte("bank account"),
		[]byte("account number"),
		[]byte("acct no"),
		[]byte("account no"),
	})
}

// holderNameKeywords are keywords indicating holder/beneficiary name context.
// Their presence near a bank account number increases confidence. They match
// byte for byte.
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
