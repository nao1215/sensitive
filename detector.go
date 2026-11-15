package embargo

import "github.com/nao1215/embargo/internal/detect"

// Detector finds application-specific values. Scan must terminate, leave input unchanged,
// return nonempty kinds and valid byte spans/scores, and support concurrent calls when shared.
type Detector interface {
	// Scan returns findings in data without retaining or modifying it.
	Scan(data []byte) []Finding
}

func builtins() []detect.Detector {
	return []detect.Detector{
		&detect.Credential{},
		&detect.ServiceToken{},
		&detect.HighEntropy{},
		detect.NewPAN(),
		detect.NewEmail(),
		detect.NewJPPhone(),
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
	}
}
