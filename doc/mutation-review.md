# Detector and scanner mutation review

The baseline is main at 610b5f5. Both runs use gremlins v0.6.0, four workers, GOMAXPROCS=4 and timeout coefficient 10. The final run uses a fixed worktree so edits cannot change the suite while mutants execute. Root-module tests determine mutation results; the nested property and SDK tests are not counted as mutation tests. Timeouts are reported separately and are not counted as killed.

<!-- mutation-comparison:start -->
| Snapshot | Killed | Lived | Uncovered | Timed out | Efficacy | Mutator coverage |
|---|---:|---:|---:|---:|---:|---:|
| Before, `610b5f5` | 1395 | 203 | 113 | 38 | 87.30% | 93.40% |
| After, `7d54404` | 1517 | 156 | 124 | 37 | 90.68% | 93.10% |

Efficacy changed by +3.38 percentage points. The code changed the mutation population, so the difference of 122 killed mutants is not a count of matched old mutants newly killed. Uncovered mutations include nested-module adapters outside this root-suite run; mutator coverage changed by -0.30 points. The after run had 0 nonviable and 0 skipped mutants; both counts were zero before.

[Before log](performance/mutation-before.txt), [after log](performance/mutation-after.txt), and [all 156 surviving mutations](performance/mutation-survivors.txt) retain individual outcomes. Source snapshots and the same tool settings make the two runs reproducible.
<!-- mutation-comparison:end -->

The review added assertions for inclusive minimum confidence, rejection of empty custom spans, all sort tie breakers, ASCII alphabet endpoints, mixed hexadecimal case endpoints, credential minimum lengths, adjacent candidates, PAN prefix boundaries, phone confidence, the My Number remainder-one checksum, values preceding context keywords, attached business labels after field delimiters, hints ending exactly at the input boundary, query-parameter business labels, and zero decoding allocations when no built-ins are selected. The review also removed percent-map capacity addition to avoid integer overflow and made invalid accuracy-set selections fail instead of silently skipping evaluation. The scanner differential suite compares 12,000 generated inputs with the previous dispatch loop; normalization and percent-decoding properties check original offsets independently.

## Equivalent survivors

These are equivalence arguments for the public Scanner outputs, not exclusions from the reported mutation counts. The full survivor inventory is retained alongside the measurement logs; a survivor without a proof is not assumed equivalent.

| Location / mutation family | Reason |
|---|---|
| `scanner.go`, building dispatch for one detector | The single-detector path uses its substring hint cache regardless of the dispatch index; building the unused index only changes construction cost. |
| `scanner_dispatch.go`, all-detectors early-exit mask arithmetic | Once every selected bit is set, scanning more input cannot clear a bit; changing the early-exit condition only changes work performed. |
| `scanner_dispatch.go`, numeric hint upper bound at 9 | Only hintless My Number and ABA use these synthetic hints. An all-9 My Number fails its checksum, and an all-9 ABA fails its district check. Every accepted ASCII candidate contains another digit; full-width inputs use their own hint. |
| `internal/detect/label.go`, empty-prefix loop boundary | One extra iteration obtains an empty word, which matches no label and returns the same confidence. |
| `internal/detect/pan.go`, Luhn `n > 9` boundary | The value has just been doubled and is even, so it cannot equal 9. |
| `internal/detect/regex.go`, clamp boundaries at 0 and 1 | Clamping either endpoint returns the same endpoint. |
| `internal/detect/fullwidth.go`, fallback end calculation and sentinel boundary | Valid normalized spans always have an end sentinel, which overwrites the fallback end calculation; the end index never equals the map length. |
| `internal/detect/fullwidth.go`, ASCII fast-path boundary at 0x80 | The invalid UTF-8 byte 0x80 is preserved by normalization; taking the other path changes allocation, not findings. |
| `internal/detect/btc.go`, HRP expansion capacity | The scanner supplies the fixed HRP `bc`; changing capacity does not change appended values. |
| `internal/detect/eth.go`, skipping digits in EIP-55 case checks | The following upper/lowercase tests cannot reject a decimal digit, so executing them instead of skipping produces the same answer. |
| `internal/detect/eth.go`, full-block Keccak loop and remainder | EIP-55 passes exactly 40 bytes, below the 136-byte block size, so the full-block loop is not reached and its offset stays zero. |

Other survivors include defensive bounds already constrained by callers, cursor optimizations that need more adversarial sequencing, and internal details that the public Finding does not expose. Their raw locations remain visible; this review does not claim that every lived mutant is equivalent or that mutation testing proves detector accuracy.

## Round 13 log-context boundaries

The round 12 source and root tests at da95fde are unchanged at the round 13 baseline b8290bc; the completed [round 12 log](performance/round12-mutation.txt) is the baseline below. The [round 13 full log](performance/round13-mutation.txt) uses 54bd3c7, gremlins v0.6.0, four workers, GOMAXPROCS=4 and timeout coefficient 10. It precedes the review follow-ups. The default per-package mode can miss assertions in Scanner tests that call internal detectors from another package; nested-module sources also contribute uncovered mutations.

| Snapshot | Killed | Lived | Uncovered | Timed out | Efficacy | Mutator coverage |
|---|---:|---:|---:|---:|---:|---:|
| Round 12 / baseline | 1676 | 185 | 316 | 36 | 90.06% | 85.48% |
| Round 13 full, 54bd3c7 | 1794 | 287 | 220 | 42 | 86.21% | 90.44% |

Efficacy decreased by 3.85 percentage points while exercised mutations increased by 4.96 points. These are different mutation populations; neither the higher killed count nor the statement coverage improvement establishes stronger assertions everywhere. Both runs had zero nonviable and zero skipped mutations, and timeouts remain separate.

A second run used `--integration --diff b8290bc4371aa4f2fb5674e1d3c120670219c3ab` to execute all root tests for mutations on changed lines. At ac3a9bb it killed 81 and left 22 alive, with 37 uncovered, zero timeouts and 2,203 skipped. Its efficacy was 78.64%. Adding punctuation, hostname, quoted-token, hexadecimal-length and A/Z boundary assertions killed 17 of those survivors: 98 killed, 5 lived, the same uncovered/skipped counts and 95.15% efficacy. These focused results do not replace the full result above. [Initial focused log](performance/round13-mutation-changes.txt) and [first boundary follow-up](performance/round13-mutation-boundaries.txt) retain every mutation.

The remaining digit-predecessor mutations read inside the number instead of before the dot. An abbreviation such as `No.111111111118` distinguishes the two; the final tests include that case. Three other survivors have caller-specific equivalence arguments: starting the hostname loop at `end-2` visits the already-validated last two digits, hyphen and first letter before reaching the original search position; allowing `objectReference` start zero has no effect because a parsed key and delimiter always precede its argument; accepting split zero still fails the later requirement for an uppercase class-name letter. They remain counted as lived, and the arguments do not apply to arbitrary direct calls with invalid spans.

The final focused follow-up, using the a7dd142 production code plus the trailing-context SWIFT assertion, killed 127 mutations and left four alive: 96.95% efficacy, 77.98% mutator coverage, 37 uncovered, zero timeouts, zero nonviable and 2,203 skipped. The extra SWIFT test places `swift` after a list starting at byte zero; it catches a loop-boundary mutation that otherwise indexes before the input. [Final focused log](performance/round13-mutation-final-changes.txt).

| Remaining changed-line survivor | Review |
|---|---|
| `numericLogFragment`: `end+2` becomes `end-2` | The valid candidate ends in digits; the extra iterations visit only those digits, the already-checked hyphen and first hostname letter. The first later dot and the stopping delimiter are unchanged. |
| `objectReference`: `start > 0` becomes `start >= 0` | The sole caller supplies a value after a parsed key and delimiter, so start cannot be zero. |
| `objectReference`: `split <= 0` becomes `split < 0` | An empty class name still fails the uppercase-letter requirement. |
| `swiftSlashList`: `codeEnd(...) > 0` becomes `>= 0` | codeEnd yields -1 or the end of a valid code of at least eight bytes; it cannot yield zero. |

The 37 uncovered mutations comprise 34 in the cached-log command and three in ABA log-context operations. The combined root statement profile exercises those ABA operations through Scanner tests, but gremlins still marks them uncovered in this run; they are retained in the denominator. These arguments cover the four listed survivors only, not every survivor in the full mutation log.

[Support maintenance](https://github.com/sponsors/nao1215).
