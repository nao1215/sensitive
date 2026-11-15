# Detector and scanner mutation review

The baseline is main at 610b5f5. Both runs use gremlins v0.6.0, four workers, GOMAXPROCS=4 and timeout coefficient 10. The final run uses a fixed worktree so edits cannot change the suite while mutants execute. Root-module tests determine mutation results; the nested property and SDK tests are not counted as mutation tests. Timeouts are reported separately and are not counted as killed.

<!-- mutation-comparison:start -->
| Snapshot | Killed | Lived | Uncovered | Timed out | Efficacy | Mutator coverage |
|---|---:|---:|---:|---:|---:|---:|
| Before, `610b5f5` | 1395 | 203 | 113 | 38 | 87.30% | 93.40% |
| After, `3a28f60` | 1515 | 157 | 124 | 37 | 90.61% | 93.10% |

Efficacy increased by 3.31 percentage points. The code changed the mutation population, so the difference of 120 killed mutants is not a count of matched old mutants newly killed. Uncovered mutations include nested-module adapters outside this root-suite run; mutator coverage decreased by 0.30 points. Neither run had nonviable or skipped mutants.

[Before log](performance/mutation-before.txt), [after log](performance/mutation-after.txt), and [all 157 surviving mutations](performance/mutation-survivors.txt) retain individual outcomes. Source snapshots and the same tool settings make the two runs reproducible.
<!-- mutation-comparison:end -->

The review added assertions for inclusive minimum confidence, rejection of empty custom spans, all sort tie breakers, ASCII alphabet endpoints, mixed hexadecimal case endpoints, credential minimum lengths, adjacent candidates, PAN prefix boundaries, phone confidence, the My Number remainder-one checksum, values preceding context keywords, attached business labels after field delimiters, and hints ending exactly at the input boundary. The scanner differential suite compares 12,000 generated inputs with the previous dispatch loop; normalization and percent-decoding properties check original offsets independently.

## Equivalent survivors

These are equivalence arguments for the public Scanner outputs, not exclusions from the reported mutation counts. The full survivor inventory is retained alongside the measurement logs; a survivor without a proof is not assumed equivalent.

| Location / mutation family | Reason |
|---|---|
| `scanner.go`, building dispatch for one detector | The single-detector path uses its substring hint cache regardless of the dispatch index; building the unused index only changes construction cost. |
| `scanner_dispatch.go`, all-detectors early-exit mask arithmetic | Once every selected bit is set, scanning more input cannot clear a bit; changing the early-exit condition only changes work performed. |
| `scanner_dispatch.go`, numeric hint upper bound at 9 | Only hintless My Number and ABA use these synthetic hints. An all-9 My Number fails its checksum, and an all-9 ABA fails its district check. Every accepted ASCII candidate contains another digit; full-width inputs use their own hint. |
| `internal/detect/label.go`, empty-prefix loop boundary | One extra iteration obtains an empty word, which matches no label and returns the same confidence. |
| `percent.go`, map capacity arithmetic | Changing spare capacity does not change appended indices or the end sentinel; growth may allocate more memory. |
| `internal/detect/pan.go`, Luhn `n > 9` boundary | The value has just been doubled and is even, so it cannot equal 9. |
| `internal/detect/regex.go`, clamp boundaries at 0 and 1 | Clamping either endpoint returns the same endpoint. |
| `internal/detect/fullwidth.go`, fallback end calculation and sentinel boundary | Valid normalized spans always have an end sentinel, which overwrites the fallback end calculation; the end index never equals the map length. |
| `internal/detect/fullwidth.go`, ASCII fast-path boundary at 0x80 | The invalid UTF-8 byte 0x80 is preserved by normalization; taking the other path changes allocation, not findings. |
| `internal/detect/btc.go`, HRP expansion capacity | The scanner supplies the fixed HRP `bc`; changing capacity does not change appended values. |
| `internal/detect/eth.go`, skipping digits in EIP-55 case checks | The following upper/lowercase tests cannot reject a decimal digit, so executing them instead of skipping produces the same answer. |
| `internal/detect/eth.go`, full-block Keccak loop and remainder | EIP-55 passes exactly 40 bytes, below the 136-byte block size, so the full-block loop is not reached and its offset stays zero. |

Other survivors include defensive bounds already constrained by callers, cursor optimizations that need more adversarial sequencing, and internal details that the public Finding does not expose. Their raw locations remain visible; this review does not claim that every lived mutant is equivalent or that mutation testing proves detector accuracy.

[Support maintenance](https://github.com/sponsors/nao1215).
