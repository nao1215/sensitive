# Synthetic labeled recall corpus

`recall.json` contains synthetic shapes and public specification test values, never live credentials or personal records. Every detector has two positive values and two look-alike negatives; labels describe the documented detector scope, including required context. Positive AWS values use the published EXAMPLE suffix; domains use example.com/example.org and IPs use documentation ranges. Address values are checksum examples, not evidence of account ownership.

`TestLabeledRecall` measures each detector separately through Scanner, without overlap suppression. The baseline is 2/2 recall and 0/2 false positives per detector. Any individual label mismatch fails, even if another example would hide it in an aggregate score. Grow the fixture with reviewed labels rather than deriving labels from current detector output.

Synthetic Stripe examples are stored as parts and joined by the test, matching the existing fuzz-seed convention and avoiding false alarms from credential scanners.
