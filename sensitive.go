package sensitive

import "github.com/nao1215/sensitive/detector"

// Detector is the interface that each sensitive data detector must implement.
// This is a type alias for [detector.Detector].
type Detector = detector.Detector

// Finding represents a single instance of detected sensitive data.
// This is a type alias for [detector.Finding].
type Finding = detector.Finding

// DetectorName is the type-safe identifier for a detector.
// This is a type alias for [detector.DetectorName].
type DetectorName = detector.DetectorName
