package detect

import (
	"slices"
	"strings"
	"time"
)

func countryNumber(value string) int {
	result := 0
	for i := range len(value) {
		result = result*decimalRadix + int(value[i]-'0')
	}
	return result
}

func validSSN(value string) bool {
	return value[:3] != "000" && value[:3] != "666" && value[0] != '9' && value[3:5] != "00" && value[5:] != "0000"
}

func validITIN(value string) bool {
	group := countryNumber(value[3:5])
	for _, interval := range [][2]int{{50, 65}, {70, 88}, {90, 92}, {94, 99}} {
		if value[0] == '9' && group >= interval[0] && group <= interval[1] {
			return true
		}
	}
	return false
}

func validNINO(value string) bool {
	if strings.ContainsAny(value[:2], "DFIQUV") || value[1] == 'O' || !strings.ContainsRune("ABCD", rune(value[8])) {
		return false
	}
	return !slices.Contains([]string{"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}, value[:2])
}

func validIndiaPAN(value string) bool {
	return strings.ContainsRune("PCHABGJLFT", rune(value[3])) && value[5:9] != "0000"
}

func validNHS(value string) bool {
	if sameCountryDigits(value) {
		return false
	}
	sum := 0
	for i := range 9 {
		sum += int(value[i]-'0') * (decimalRadix - i)
	}
	return (mod11Base-sum%mod11Base)%mod11Base == int(value[9]-'0')
}

func countryMod11(value string, cycle int) int {
	sum := 0
	for i := range len(value) {
		sum += int(value[len(value)-1-i]-'0') * (doubledDigit + i%cycle)
	}
	residue := sum % mod11Base
	if residue < doubledDigit {
		return 0
	}
	return mod11Base - residue
}

func validCPF(value string) bool {
	return !sameCountryDigits(value) && countryMod11(value[:9], decimalRadix) == int(value[9]-'0') && countryMod11(value[:10], decimalRadix) == int(value[10]-'0')
}

func validCNPJ(value string) bool {
	// ASCII minus 48 gives A=17 through Z=42 in the 2026 alphanumeric format.
	return !sameCountryDigits(value) && countryMod11(value[:12], cnpjCycle) == int(value[12]-'0') && countryMod11(value[:13], cnpjCycle) == int(value[13]-'0')
}

func validChinaID(value string) bool {
	if !slices.Contains(strings.Fields("11 12 13 14 15 21 22 23 31 32 33 34 35 36 37 41 42 43 44 45 46 50 51 52 53 54 61 62 63 64 65 71 81 82"), value[:2]) || value[14:17] == "000" || !countryDate(value[6:14]) {
		return false
	}
	weights := [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i, w := range weights {
		sum += int(value[i]-'0') * w
	}
	return "10X98765432"[sum%11] == value[17]
}

func countryDate(value string) bool {
	date, err := time.Parse("20060102", value)
	return err == nil && date.Year() > 0
}

func validRRNDate(value string) bool {
	var century string
	switch value[6] {
	case '9', '0':
		century = "18"
	case '1', '2':
		century = "19"
	case '3', '4':
		century = "20"
	default:
		return false
	}
	return countryDate(century + value[:6])
}

func validVerhoeff(value string) bool {
	// Multiplication in D5, represented by its ten permutations, and powers of the Verhoeff permutation.
	multiplication := [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	permutation := [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	state := 0
	for i := range len(value) {
		state = multiplication[state][permutation[i%8][value[len(value)-1-i]-'0']]
	}
	return state == 0
}
