package detect

// viewFinding returns name's finding for the span [start, end) of a normalized
// view in original offsets; a nil posMap means the view is the original input.
func viewFinding(name DetectorName, posMap []int, start, end int, confidence float64) Finding {
	origStart, origEnd := mapOriginalRange(posMap, start, end)
	return Finding{DetectorName: name, Start: origStart, End: origEnd, Confidence: confidence}
}

// labeledViewFinding is viewFinding for numeric identifiers: a business label
// right before the original start lowers score, as businessConfidence decides.
func labeledViewFinding(name DetectorName, orig []byte, posMap []int, start, end int, score float64) Finding {
	f := viewFinding(name, posMap, start, end, score)
	f.Confidence = businessConfidence(orig, f.Start, score)
	return f
}
