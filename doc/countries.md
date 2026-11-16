# Country identifiers

Use `WithKinds` to select the identifiers that an application handles. For example, `WithKinds(KindUSSSN, KindUSITIN)` selects US individual tax identifiers, while `WithKinds(KindCanadaSIN)` selects Canadian SIN. The explicit list also works for applications serving several countries, so there is no separate region helper. `WithAll` enables these eleven families; `NewScanner()` retains its previous 25-family selection.

## Rules and boundaries

These parsers recognize possible identifiers, not issued identities. They do not call government registries, verify a person's identity or establish whether a number belongs to anyone. Letters must be uppercase ASCII. Numeric digits accept ASCII and full-width forms, with offsets mapped back to the original bytes. The scanner decodes one percent-encoding layer. Longer adjacent ASCII identifiers are excluded; punctuation can delimit a candidate.

| Kind | Validation | Additional formatted form | Score |
|---|---|---|---:|
| us_ssn | Nine digits; area excludes 000, 666 and 900–999; group and serial are nonzero | 123-45-6789 | 0.6 |
| us_itin | Starts with 9; middle group 50–65, 70–88, 90–92 or 94–99 | 912-50-1234 | 0.6 |
| uk_nino | Allowed two-letter prefix, six digits, suffix A–D | AB 12 34 56 C | 0.7 |
| uk_nhs | Ten digits; weighted MOD 11; check value 10 is invalid | 943 476 5919 | 0.95 |
| in_aadhaar | Twelve digits beginning 2–9; Verhoeff check | 2345 6789 0124 | 0.95 |
| in_pan | Five letters, four digits, final letter; holder-type letter and nonzero serial | No extra separator form | 0.7 |
| br_cpf | Eleven digits; two MOD 11 checks | 280.012.389-38 | 0.95 |
| br_cnpj | Twelve uppercase alphanumeric characters and two MOD 11 digits | 12.ABC.345/01DE-35 | 0.95 |
| cn_resident_id | Eighteen characters; province prefix, calendar date, nonzero sequence, MOD 11-2 | No extra separator form | 0.95 |
| kr_rrn | Birth date, century/sex field, legacy weighted MOD 11 check | 900101-1234568 | 0.95 |
| ca_sin | Nine digits; first digit excludes 0 and 8; Luhn | 123-456-782 | 0.95 |

NINO excludes D, F, I, Q, U and V in both prefix positions, O in the second position, and prefixes BG, GB, KN, NK, NT, TN and ZZ. Indian PAN checks the fourth letter against P, C, H, A, B, G, J, L, F and T; its final letter is checked for structure, not an undocumented checksum. Repeated single-digit values are rejected for NHS, Aadhaar, CPF, CNPJ and SIN. A nearby business label such as `order_id` lowers any accepted candidate to 0.4, retaining the established scanner policy that an ambiguous label must not discard a possible secret.

CNPJ accepts the numeric format and the alphanumeric format introduced for new registrations in July 2026. Checksum arithmetic maps each character to its ASCII code minus 48, so A contributes 17, and uses the same two MOD 11 checks. Chinese resident IDs validate the province prefix and date but do not consult historical district-assignment tables. A checksum-valid date and district combination can therefore be recognized even if no such identifier could have been issued.

Korea replaced the encoded regional suffix with random digits for new or reassigned RRN from October 2020. A legacy-checksum-only recognizer would miss those values. A structurally valid RRN next to `rrn` or `주민등록번호` is therefore accepted at 0.6 even when the legacy check fails. Unlabeled modern RRN can be missed; the score does not identify when a number was issued. Foreigner registration numbers are outside this kind.

## Definitions and independent checks

The definitions come from [SSA randomization rules](https://www.ssa.gov/employer/randomizationfaqs.html), [IRS ITIN guidance](https://www.irs.gov/irm/part3/irm_03-012-002r), [HMRC NINO structure](https://www.gov.uk/hmrc-internal-manuals/national-insurance-manual/nim39110), the [NHS data dictionary](https://archive.datadictionary.nhs.uk/DD%20Release%20December%202019/data_dictionary/attributes/n/nhs/nhs_number_de.asp%40shownav%3D1.html), [NIC application validation guidance](https://cdnbbsr.s3waas.gov.in/s3c92a10324374fac681719d63979d00fe/uploads/2021/09/2021090182.pdf) and [India's PAN guide](https://www.incometaxindia.gov.in/documents/d/guest/1-permanent-account-number-pan-pdf).

Brazil's [e-Financeira manual](https://sped.rfb.gov.br/estatico/54/B1B0F2B283ECDC9B8A8A96D576F60FE41B8A73/Versao%20118%20-%2020220920%20-%20e-Financeira%20-%20Manual%20de%20Preenchimento.pdf) gives the ascending-weight CPF definition; the [CNPJ check-digit manual](https://www.gov.br/receitafederal/pt-br/centrais-de-conteudo/publicacoes/documentos-tecnicos/cnpj/manual-dv-cnpj.pdf/@@download/file) defines the alphanumeric arithmetic. See also [GB 11643-1999](https://zjw.beijing.gov.cn/Portals/0/zhuanti/fazhan/%E8%BA%AB%E4%BB%BD%E8%AF%81GB11643-1999.pdf), [Korea's Ministry of the Interior announcement](https://www.mois.go.kr/frt/bbs/type002/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000205&nttId=78282) and [Canada's SIN guidance](https://www.canada.ca/en/employment-social-development/services/sin/reports/code-of-practice.html). Canada's public guide describes the identifier; the offline python-stdnum oracle supplies an additional implementation check for Luhn and reserved prefixes.

[Microsoft Presidio's entity list](https://presidio.dataprivacystack.org/supported_entities/) was read only to compare coverage. No recognizer code was copied. The independent [Python reference](../scripts/country_reference.py) expresses CPF with ascending weights, China with the MOD 11-2 recurrence, Verhoeff with rotations and reflections in D5, and Luhn with decimal digit sums. Go uses descending CPF weights, positional Chinese weights, Verhoeff tables and the subtract-nine Luhn form. [Lean references](../tests/lean/Countries.lean) generate arithmetic vectors for seven checksum families, including numeric and alphanumeric CNPJ. Lean checks D5 identity, the permutation's period and check-digit ranges; it does not prove that the Go parser implements those definitions or that a number was issued.

## Frozen evaluation

The generator uses different seeds and surrounding log templates for development and held data. Both 6,720-row files were prepared before detector implementation; [freeze metadata](../tests/testdata/countries-freeze.json) and the [manifest](../tests/testdata/countries-manifest.json) retain their hashes. Each kind has 96 generated values in bare, formatted and percent-encoded forms, plus rejected mutations, embedded identifiers, public order IDs and clean logs. RRN adds 32 labeled modern values with invalid legacy checks. Public-ID negatives deliberately share valid identity syntax, exposing the precision cost of retaining ambiguous values. No parser rule was tuned after the first held evaluation; those committed rows are regression data after this round.

The measurements select each kind explicitly with WithKinds. They describe enabled detectors; the default scanner does not enable these new families.

<!-- countries:start -->
| Kind | Threshold | Dev TP / FP / FN | Dev P / R | Held TP / FP / FN | Held P / R | Exposed bytes dev / held |
|---|---:|---:|---|---:|---|---:|
| br_cnpj | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| br_cnpj | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| br_cnpj | 0.7 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| br_cpf | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| br_cpf | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| br_cpf | 0.7 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| ca_sin | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| ca_sin | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| ca_sin | 0.7 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| cn_resident_id | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| cn_resident_id | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| cn_resident_id | 0.7 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| in_aadhaar | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| in_aadhaar | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| in_aadhaar | 0.7 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| in_pan | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| in_pan | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| in_pan | 0.7 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| kr_rrn | 0 | 320 / 96 / 0 | 76.9% / 100.0% | 320 / 96 / 0 | 76.9% / 100.0% | 0 / 0 |
| kr_rrn | 0.5 | 320 / 0 / 0 | 100.0% / 100.0% | 320 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| kr_rrn | 0.7 | 288 / 0 / 32 | 100.0% / 90.0% | 288 / 0 / 32 | 100.0% / 90.0% | 448 / 448 |
| uk_nhs | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| uk_nhs | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| uk_nhs | 0.7 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| uk_nino | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| uk_nino | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| uk_nino | 0.7 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| us_itin | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| us_itin | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| us_itin | 0.7 | 0 / 0 / 288 | n/a / 0.0% | 0 / 0 / 288 | n/a / 0.0% | 4512 / 4512 |
| us_ssn | 0 | 288 / 96 / 0 | 75.0% / 100.0% | 288 / 96 / 0 | 75.0% / 100.0% | 0 / 0 |
| us_ssn | 0.5 | 288 / 0 / 0 | 100.0% / 100.0% | 288 / 0 / 0 | 100.0% / 100.0% | 0 / 0 |
| us_ssn | 0.7 | 0 / 0 / 288 | n/a / 0.0% | 0 / 0 / 288 | n/a / 0.0% | 4512 / 4512 |
<!-- countries:end -->

At threshold 0.5 the synthetic business-label false positives disappear without losing any expected value in either split. At 0.7, SSN, ITIN and modern RRN lose recall. The public scanner's threshold remains 0: older high-tier kinds still need low-confidence matches, and a genuine identifier can occur under a misleading label. Applications that choose a country-specific policy can opt into 0.5 after evaluating their own logs. No new kind joins the default set because threshold-zero held precision is below 99%, even where this small system-log cache has no findings. The admission rule requires at least 99% held precision and no observed real-log false positives, plus a review of uncovered cases; passing those finite checks would not establish deployment precision.

## Cached real logs

The eight checksum-pinned datasets are the same 92,409,848 bytes and 819,576 lines used in round 13. Raw logs and sampled excerpts remain outside Git. The [real-log evidence](real-logs.md) records licenses, hashes and sample labels. Each dataset/kind stratum uses at most 40 deterministic sampled findings; FP/GB is count multiplied by the sampled false-positive fraction, divided by decimal GB. This is an estimate, not recall or a confidence bound. The previous held log split has already been inspected in earlier rounds.

<!-- country-logs:start -->
| Kind | Dev findings | Dev sampled FP / sample | Dev estimated FP / GB | Held findings | Held sampled FP / sample | Held estimated FP / GB |
|---|---:|---|---:|---:|---|---:|
| br_cnpj | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| br_cpf | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| ca_sin | 15 | 15 / 15 | 1,862.8 | 9 | 9 / 9 | 106.7 |
| cn_resident_id | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| in_aadhaar | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| in_pan | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| kr_rrn | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| uk_nhs | 0 | 0 / 0 | 0.0 | 193 | 40 / 40 | 2,287.9 |
| uk_nino | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| us_itin | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| us_ssn | 165 | 73 / 73 | 20,490.6 | 32 | 32 / 32 | 379.3 |
<!-- country-logs:end -->

The sampled SSN matches are Android event times and lock identifiers, Linux inode/process values and BGL counters. SIN matches overlap those numeric fields, Zookeeper snapshot filenames and one OpenSSH hostname fragment. NHS matches are BGL epoch seconds. These are false positives for national identifiers even when a machine or user reference elsewhere on the same line could be sensitive. Zero findings for the remaining kinds only describes this corpus.

[Support maintenance](https://github.com/sponsors/nao1215).
