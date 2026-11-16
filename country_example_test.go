package embargo_test

import (
	"fmt"

	"github.com/nao1215/embargo"
)

func ExampleKindUSSSN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUSSSN))
	input := "us_ssn=663-27-1262"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: us_ssn=[REDACTED]
}

func ExampleKindUSITIN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUSITIN))
	input := "us_itin=984-73-5739"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: us_itin=[REDACTED]
}

func ExampleKindUKNINO() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUKNINO))
	input := "uk_nino=ZM 88 85 70 B"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: uk_nino=[REDACTED]
}

func ExampleKindUKNHS() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindUKNHS))
	input := "uk_nhs=769 461 7519"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: uk_nhs=[REDACTED]
}

func ExampleKindIndiaAadhaar() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindIndiaAadhaar))
	input := "in_aadhaar=2587 2639 8415"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: in_aadhaar=[REDACTED]
}

func ExampleKindIndiaPAN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindIndiaPAN))
	input := "in_pan=ATTJE9054P"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: in_pan=[REDACTED]
}

func ExampleKindBrazilCPF() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindBrazilCPF))
	input := "br_cpf=860.174.949-61"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: br_cpf=[REDACTED]
}

func ExampleKindBrazilCNPJ() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindBrazilCNPJ))
	input := "br_cnpj=40.771.605/5203-66"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: br_cnpj=[REDACTED]
}

func ExampleKindChinaResidentID() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindChinaResidentID))
	input := "cn_resident_id=510104199602017742"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: cn_resident_id=[REDACTED]
}

func ExampleKindKoreaRRN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindKoreaRRN))
	input := "kr_rrn=220329-2878073"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: kr_rrn=[REDACTED]
}

func ExampleKindCanadaSIN() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCanadaSIN))
	input := "ca_sin=413-643-081"
	fmt.Println(embargo.Mask(input, scanner.ScanString(input)))
	// Output: ca_sin=[REDACTED]
}
