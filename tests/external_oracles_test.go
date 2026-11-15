package tests

import (
	"bytes"
	"encoding/json"
	"net/mail"
	"net/netip"
	"os/exec"
	"strconv"
	"testing"

	"pgregory.net/rapid"

	"github.com/nao1215/embargo"
)

const referenceBICKind = "swiftbic"

func TestExternalPythonOracles(t *testing.T) {
	t.Parallel()
	type sample struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	}
	samples := make([]sample, 0, 11009)
	for n := range 100 {
		for check := range 10 {
			samples = append(samples, sample{Kind: "pan", Value: "400000000000" + leftPad(strconv.Itoa(n*10+check), 4)})
		}
		for check := range 100 {
			samples = append(samples, sample{Kind: referenceIBANKind, Value: "DE" + leftPad(strconv.Itoa(check), 2) + leftPad(strconv.Itoa(n), 18)})
		}
	}
	for _, value := range []string{"DEUTDEFF", "DEUTDEFF500", "NWBKGB2L", "BOFAUS3NXXX", "AAAAZZ22", "DEUTDE", "DEUTDEFF5000", "DEUTDE0F", "DEUTDEFF0_0"} {
		samples = append(samples, sample{Kind: referenceBICKind, Value: value})
	}
	for n := range 100 {
		for _, country := range []string{"DE", "GB", "US", "JP", "ZZ"} {
			value := "TEST" + country + leftPad(strconv.Itoa(n), 2)
			if n%2 == 1 {
				value += leftPad(strconv.Itoa(n), 3)
			}
			samples = append(samples, sample{Kind: referenceBICKind, Value: value})
		}
	}
	input, err := json.Marshal(samples) //nolint:errchkjson // Retain explicit error handling at the subprocess boundary.
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "python3", "oracles/validate.py")
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for range samples {
		var result sample
		if err := decoder.Decode(&result); err != nil {
			t.Fatal(err)
		}
		scanner := embargo.NewScanner(embargo.WithKinds(embargo.Kind(result.Kind)), embargo.WithMinConfidence(0.8))
		prefix := ""
		if result.Kind == referenceBICKind {
			prefix = "SWIFT: "
		}
		findings := scanner.ScanString(prefix + result.Value)
		valid := len(findings) == 1 && findings[0].Start == len(prefix) && findings[0].End == len(prefix)+len(result.Value)
		// python-stdnum accepts MOD 97 residues with reserved IBAN check digits;
		// embargo rejects 00, 01 and 99 by its documented generation policy.
		if result.Kind == referenceIBANKind && (result.Value[2:4] == "00" || result.Value[2:4] == "01" || result.Value[2:4] == "99") {
			if valid {
				t.Fatal("reserved IBAN check digits accepted")
			}
			continue
		}
		if valid != result.Valid {
			t.Errorf("oracle mismatch %s %s: detected=%v oracle=%v", result.Kind, result.Value, valid, result.Valid)
		}
	}
}

func leftPad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

func TestStandardLibraryOracles(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// The intersection excludes display names, comments, quoted local parts,
		// single-label domains, scoped IPv6 and IPv4-mapped IPv6.
		email := chars(t, "abcxyz012", rapid.IntRange(1, 32).Draw(t, "local")) + "@example.com"
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email {
			t.Fatal("generator outside common email grammar")
		}
		findings := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)).ScanString(email)
		if len(findings) != 1 || findings[0].Start != 0 || findings[0].End != len(email) {
			t.Fatal("net/mail intersection mismatch")
		}
		var raw [4]byte
		for i := range raw {
			raw[i] = rapid.Byte().Draw(t, "octet")
		}
		address := netip.AddrFrom4(raw)
		valid := !address.IsLoopback() && !address.IsUnspecified()
		findings = embargo.NewScanner(embargo.WithKinds(embargo.KindIPAddr)).ScanString(address.String())
		if (len(findings) == 1) != valid {
			t.Fatal("netip policy mismatch")
		}
		var raw6 [16]byte
		for i := range raw6 {
			raw6[i] = rapid.Byte().Draw(t, "IPv6 byte")
		}
		// A fixed nonzero leading word keeps generated addresses outside the
		// mapped IPv4 intersection, which has a separate documented policy.
		raw6[0], raw6[1] = 0x20, 0x01
		address6 := netip.AddrFrom16(raw6)
		findings = embargo.NewScanner(embargo.WithKinds(embargo.KindIPAddr)).ScanString(address6.String())
		if len(findings) != 1 || findings[0].Start != 0 || findings[0].End != len(address6.String()) {
			t.Fatal("netip IPv6 mismatch")
		}
	})
}
