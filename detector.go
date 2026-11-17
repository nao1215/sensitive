package embargo

import "github.com/nao1215/embargo/internal/detect"

// Detector finds application-specific values. Scan must terminate, leave input unchanged,
// return nonempty kinds and valid byte spans/scores, and support concurrent calls when shared.
type Detector interface {
	// Scan returns findings in data without retaining or modifying it.
	Scan(data []byte) []Finding
}

// builtins returns every built-in detector; matchKey optionally replaces the credential key policy.
func builtins(matchKey func(string) bool) []detect.Detector {
	return []detect.Detector{
		&detect.Credential{MatchKey: matchKey},
		detect.NewServiceToken(),
		&detect.HighEntropy{},
		detect.NewPAN(),
		detect.NewEmail(),
		detect.NewJPPhone(),
		detect.NewUSPhone(),
		detect.NewMyNumber(),
		detect.NewJWT(),
		detect.NewAWSKey(),
		detect.NewIBAN(),
		detect.NewIPAddr(),
		detect.NewSWIFTBIC(),
		detect.NewABARouting(),
		detect.NewUKSortCode(),
		detect.NewCVV(),
		detect.NewCardExpiry(),
		detect.NewPaymentToken(),
		detect.NewBankAccount(),
		detect.NewACHTrace(),
		detect.NewMerchantID(),
		detect.NewBTC(),
		detect.NewETH(),
		detect.NewGitHubToken(),
		detect.NewSlackToken(),
		detect.NewGoogleAPIKey(),
		detect.NewPrivateKeyPEM(),
		detect.NewCountry("us_ssn"),
		detect.NewCountry("us_itin"),
		detect.NewCountry("uk_nino"),
		detect.NewCountry("uk_nhs"),
		detect.NewCountry("in_aadhaar"),
		detect.NewCountry("in_pan"),
		detect.NewCountry("br_cpf"),
		detect.NewCountry("br_cnpj"),
		detect.NewCountry("cn_resident_id"),
		detect.NewCountry("kr_rrn"),
		detect.NewCountry("ca_sin"),
	}
}
