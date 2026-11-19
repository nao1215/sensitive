package detect

import (
	"strings"
	"testing"
)

func TestDetectorCredentialYAMLBlockProperty(t *testing.T) {
	t.Parallel()
	scanner := &Credential{}
	for _, indent := range []string{"", "  ", "    "} {
		for _, indicator := range []string{"|", ">", "|-", ">+", "|2"} {
			input := indent + "password: " + indicator + "\n" + indent + "  opaqueBlockFixture\n" + indent + "  opaqueBodyFixture\n" + indent + "public: retained\n"
			got := maskCredentialFindings(input, scanner.Scan([]byte(input)))
			if strings.Contains(got, "opaque") || !strings.Contains(got, "public: retained") {
				t.Errorf("block boundary: %q => %q", input, got)
			}
		}
	}
}

func TestCredentialBlockSpanProperty(t *testing.T) {
	t.Parallel()
	for _, indent := range []string{"", " ", "    "} {
		for _, newline := range []string{"\n", "\r\n"} {
			for _, indicator := range []string{"|", ">", "|+", ">-", "|2"} {
				before := "public: kept" + newline + indent + "password: "
				value := indicator + newline + indent + "  firstFixture" + newline + newline + indent + "  lastFixture"
				for _, after := range []string{"", newline + indent + "public: retained"} {
					input := before + value + after
					wantValue := value
					if after != "" {
						wantValue += newline
					}
					got := (&Credential{}).Scan([]byte(input))
					if len(got) != 1 || got[0].Start != len(before) || got[0].End != len(before)+len(wantValue) || input[got[0].Start:got[0].End] != wantValue {
						t.Fatalf("block span: %q: %+v", input, got)
					}
				}
			}
		}
	}
}
