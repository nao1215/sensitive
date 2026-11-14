package sensitive

import "github.com/nao1215/sensitive/detector"

// Detector aliases [detector.Detector], the contract for custom detectors.
type Detector = detector.Detector

// Finding aliases [detector.Finding], a match with byte offsets and detector-specific detail.
type Finding = detector.Finding

// DetectorName aliases [detector.DetectorName], a detector identifier.
type DetectorName = detector.DetectorName

// SensitiveKind aliases [detector.SensitiveKind], a finding category.
//
// revive:disable-next-line:exported
type SensitiveKind = detector.SensitiveKind
