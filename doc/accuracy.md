# Synthetic accuracy corpus

The generator uses Python random.Random(20261115) and only the standard library. It does not import embargo, query services or use production data. Review scripts/generate_accuracy.py for the independent Luhn, My Number, ABA, IBAN and Base58Check encoders, format constructors, malformed inputs and surroundings. The generated JSONL is checked in so reviewers can inspect individual original-byte labels. CI runs --check; make accuracy-doc regenerates it before scoring.

Per detector: two hand-written positives plus 24 generated values in six surroundings give 146 positive inputs. Two hand-written negatives, 16 generated invalid values in four surroundings, 16 original shared controls and 256 generated shared controls give 338 negative inputs. Across 23 detectors this is 11,132 evaluations. Surroundings reuse values, so these are sample counts rather than independent statistical trials. The case mix and limited format variants cannot establish production precision, prevalence or recall.

## Known limits retained in the scores

- URL encoding: the scanner has selected separator recognition, not general URL decoding. Encoded full-width digits, plus signs, slashes, spaces and context keywords can be missed or only partly matched. Decode the application field and scan it before re-encoding; returned positions apply to the scanned representation. The encoded positives remain labeled as sensitive in this corpus to expose the limitation.
- SWIFT/BIC: the nearby SWIFT keyword permits all-letter shapes. Words such as accepted (country PT) or finished (country SH) can match the format. Checking actual institution assignment would require an external registry; it is not part of this format detector.
- PAN: invalid Luhn numbers are deliberately returned as lower-confidence BIN/length candidates. They count as false positives against these semantic negative labels. WithMinConfidence can narrow policy, but this table measures the unchanged default.
- Numeric business identifiers: valid-checksum order and invoice identifiers are indistinguishable from cards or My Number by shape alone. Their intended business meaning supplies the negative label; the scanner does not have that application context.

The first expanded run failed 305 generated cases; the failing output was retained in the owner's review evidence before recording limits. accuracy_limits.jsonl lists every generated/control mismatch with a reason and the exact observed spans. TestGeneratedAccuracyRegressions rejects new mismatches, changed spans and obsolete limits. These exceptions never alter the accuracy labels or remove samples from the table. The original hand corpus and shared controls are also retained for continuity.

The generated PEM positives exercise supported headers, not key validity. JWT and service-token positives are syntactic fixtures with no authentication claim. Synthetic phone/identity/payment values are generated offline and must never be used for contacting people, transactions or credentials.
