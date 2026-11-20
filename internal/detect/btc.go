package detect

import (
	"github.com/nao1215/embargo/internal/ascii"
)

// BTC implements the public matching contract at
// https://pkg.go.dev/github.com/nao1215/embargo@main#KindBTC.
type BTC struct{}

// NewBTC validates mainnet Base58Check, SegWit and Taproot address checksums.
func NewBTC() *BTC {
	return &BTC{}
}

// Name returns "btc".
func (d *BTC) Name() DetectorName {
	return NameBTC
}

// Hints returns nil because no selective exhaustive substring is available.
func (d *BTC) Hints() [][]byte {
	return nil
}

// startBytes reports the bytes every address contains: legacy addresses
// start with 1 or 3, and bech32 addresses carry the separator 1 after bc.
func (d *BTC) startBytes() []byte { return []byte("13") }

// Scan returns matches in data using the rules documented on [BTC].
func (d *BTC) Scan(data []byte) []Finding {
	var findings []Finding

	for i := 0; i < len(data); i++ {
		// An address starts with bc1, 1 or 3 at a word boundary; checking it
		// here keeps the digits inside words and numbers from costing a call.
		if !btcLead(data, i) || !btcWordStart(data, i) {
			continue
		}
		// Try bech32/bech32m first (most specific prefix).
		if matchBech32Prefix(data, i) {
			if f, end, ok := d.scanBech32(data, i); ok {
				findings = append(findings, f)
				i = end - 1
				continue
			}
		}

		// Try legacy addresses (P2PKH starts with '1', P2SH starts with '3').
		if data[i] == '1' || data[i] == '3' {
			if f, end, ok := d.scanLegacy(data, i); ok {
				findings = append(findings, f)
				i = end - 1
				continue
			}
		}
	}

	return findings
}

// btcLead reports the first bytes of an address at i: bc1, 1 or 3.
func btcLead(data []byte, i int) bool {
	return data[i] == '1' || data[i] == '3' || matchBech32Prefix(data, i)
}

// matchBech32Prefix checks whether data[i:] starts with "bc1" or "BC1"
// (case-insensitive, but bech32 addresses must be fully lowercase or uppercase).
func matchBech32Prefix(data []byte, i int) bool {
	if i+3 > len(data) {
		return false
	}
	return (data[i] == 'b' || data[i] == 'B') &&
		(data[i+1] == 'c' || data[i+1] == 'C') &&
		data[i+2] == '1'
}

// scanBech32 attempts to parse a bech32/bech32m Bitcoin address starting at position i.
// Returns the Finding, end position, and success flag.
// The caller has checked the word boundary before i.
func (d *BTC) scanBech32(data []byte, i int) (Finding, int, bool) {
	// Determine case (bech32 must be all-lowercase or all-uppercase after HRP).
	isUpper := data[i] == 'B'

	// Extract bech32 characters starting after "bc1".
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	j := i + 3
	for j < len(data) && ascii.IsAlphaNum(data[j]) {
		j++
	}

	addrLen := j - i

	// Valid bech32 BTC addresses are exactly 42 (P2WPKH) or 62 (P2WSH/P2TR) chars.
	if addrLen != 42 && addrLen != 62 {
		return Finding{}, 0, false
	}

	// Word boundary: following character must not be alphanumeric or underscore.
	if !btcWordEnd(data, j) {
		return Finding{}, 0, false
	}

	addr := string(data[i:j])

	// Verify consistent casing across the entire address including HRP.
	// BIP-173 requires the whole address to be single-case.
	if !isBech32ConsistentCase(addr) {
		return Finding{}, 0, false
	}

	// Normalize to lowercase for checksum validation.
	lowerAddr := ascii.LowerString(addr)

	// Decode the data part (after "bc1").
	dataPart := lowerAddr[3:]
	decoded, ok := decodeBech32Chars(dataPart)
	if !ok {
		return Finding{}, 0, false
	}

	// Verify checksum and determine encoding version.
	checksumConst, valid := bech32VerifyChecksum("bc", decoded)
	if !valid {
		return Finding{}, 0, false
	}

	if !validBech32Witness(decoded[0], checksumConst) {
		return Finding{}, 0, false
	}

	_ = isUpper // casing is already validated

	return Finding{
		DetectorName: d.Name(),
		Start:        i,
		End:          j,
		//nolint:mnd // The detector contract documents this heuristic score.
		Confidence: 0.95,
	}, j, true
}

// validBech32Witness reports whether the witness version matches the checksum
// variant: BIP-173 version 0 uses bech32 and BIP-350 versions 1-16 use bech32m.
func validBech32Witness(witnessVersion, checksumConst int) bool {
	// Determine address type from witness version and checksum constant.
	// BIP-173: witness version 0 uses bech32.
	// BIP-350: witness versions 1-16 use bech32m.
	switch {
	case witnessVersion == 0 && checksumConst == bech32ChecksumConst:
	case witnessVersion >= 1 && witnessVersion <= 16 && checksumConst == bech32mChecksumConst:
	default:
		// Invalid witness version / checksum variant combination.
		return false
	}
	return true
}

// btcWordStart reports whether an address may start at i: the preceding byte is
// not an identifier byte unless an encoded separator precedes the address.
func btcWordStart(data []byte, i int) bool {
	return leadingBoundary(data, i, isIdentifierByte)
}

// btcWordEnd reports whether an address may end at j: the following byte is not
// an identifier byte.
func btcWordEnd(data []byte, j int) bool {
	return j >= len(data) || !isIdentifierByte(data[j])
}

// scanLegacy attempts to parse a legacy (P2PKH/P2SH) Bitcoin address starting at position i.
// Returns the Finding, end position, and success flag.
// The caller has checked the word boundary before i, which matches the
// right-boundary check and prevents false positives from non-Base58
// characters like 0, I, O, l that precede the address.
func (d *BTC) scanLegacy(data []byte, i int) (Finding, int, bool) {
	// Extract Base58 characters.
	j := i
	for j < len(data) && isBase58Char(data[j]) {
		j++
	}

	length := j - i
	// Legacy addresses are 25-34 characters (typically 33-34).
	if length < 25 || length > 34 {
		return Finding{}, 0, false
	}

	// Word boundary: following character must not be alphanumeric or underscore.
	if !btcWordEnd(data, j) {
		return Finding{}, 0, false
	}

	addr := string(data[i:j])

	if !validLegacyPayload(addr) {
		return Finding{}, 0, false
	}

	return Finding{
		DetectorName: d.Name(),
		Start:        i,
		End:          j,
		//nolint:mnd // The detector contract documents this heuristic score.
		Confidence: 0.95,
	}, j, true
}

// validLegacyPayload validates the Base58Check payload of a legacy address: a
// 25-byte decoding, the double SHA-256 checksum and a P2PKH or P2SH version byte.
func validLegacyPayload(addr string) bool {
	// Validate Base58Check encoding (double SHA-256 checksum).
	decoded, ok := base58Decode(addr)
	if !ok || len(decoded) != 25 {
		return false
	}

	if !validateBase58Checksum(decoded) {
		return false
	}

	// Determine address type from version byte.
	switch decoded[0] {
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	case 0x00:
	//nolint:mnd // Literal field widths and arithmetic follow the format rules documented on this detector.
	case 0x05:
	default:
		return false
	}
	return true
}
