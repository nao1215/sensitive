package detect

// viewFinding returns name's finding for the span [start, end) of a normalized
// view in original offsets; a nil posMap means the view is the original input.
func viewFinding(name DetectorName, posMap []int, start, end int, confidence float64) Finding {
	origStart, origEnd := mapOriginalRange(posMap, start, end)
	return Finding{DetectorName: name, Start: origStart, End: origEnd, Confidence: confidence}
}

// labeledViewFinding is viewFinding for a number that a record label lowers,
// as recordConfidence decides from the original input; own names the number.
func labeledViewFinding(name DetectorName, orig []byte, posMap []int, start, end int, score float64, own ...string) Finding {
	f := viewFinding(name, posMap, start, end, score)
	f.Confidence = recordConfidence(orig, f.Start, score, own...)
	return f
}
