# Country identifiers

Use `WithKinds` to select the identifiers that an application handles. For example, `WithKinds(KindUSSSN, KindUSITIN)` selects US individual tax identifiers, while `WithKinds(KindCanadaSIN)` selects Canadian SIN. The explicit list also works for applications serving several countries, so there is no separate region helper. `WithAll` enables these eleven families; `NewScanner()` retains its previous 25-family selection.

## Rules and boundaries

The [Kind godoc](https://pkg.go.dev/github.com/nao1215/embargo@main#KindUSSSN) is the matching contract for all eleven country kinds, including formats, check digits, context and confidence tiers. These parsers recognize possible identifiers, not issued identities; they do not consult government registries or verify ownership.

CNPJ added an alphanumeric format for new registrations in July 2026. [KindBrazilCNPJ](https://pkg.go.dev/github.com/nao1215/embargo@main#KindBrazilCNPJ) covers both generations. Chinese resident IDs have a different limitation: a checksum-valid date and district combination can be recognized even if no such identifier could have been issued, because historical district-assignment tables are not consulted.

Korea replaced the encoded regional suffix with random digits for new or reassigned RRN from October 2020. A legacy-checksum-only recognizer would miss those values, which motivates the contextual fallback documented on [KindKoreaRRN](https://pkg.go.dev/github.com/nao1215/embargo@main#KindKoreaRRN). Unlabeled modern RRN can be missed; confidence does not identify when a number was issued. Foreigner registration numbers are outside this kind.

## Definitions and independent checks

The definitions come from [SSA randomization rules](https://www.ssa.gov/employer/randomizationfaqs.html), [IRS ITIN guidance](https://www.irs.gov/irm/part3/irm_03-012-002r), [HMRC NINO structure](https://www.gov.uk/hmrc-internal-manuals/national-insurance-manual/nim39110), the [NHS data dictionary](https://archive.datadictionary.nhs.uk/DD%20Release%20December%202019/data_dictionary/attributes/n/nhs/nhs_number_de.asp%40shownav%3D1.html), [NIC application validation guidance](https://cdnbbsr.s3waas.gov.in/s3c92a10324374fac681719d63979d00fe/uploads/2021/09/2021090182.pdf) and [India's PAN guide](https://www.incometaxindia.gov.in/documents/d/guest/1-permanent-account-number-pan-pdf).

Brazil's [e-Financeira manual](https://sped.rfb.gov.br/estatico/54/B1B0F2B283ECDC9B8A8A96D576F60FE41B8A73/Versao%20118%20-%2020220920%20-%20e-Financeira%20-%20Manual%20de%20Preenchimento.pdf) gives the ascending-weight CPF definition; the [CNPJ check-digit manual](https://www.gov.br/receitafederal/pt-br/centrais-de-conteudo/publicacoes/documentos-tecnicos/cnpj/manual-dv-cnpj.pdf/@@download/file) defines the alphanumeric arithmetic. See also [GB 11643-1999](https://zjw.beijing.gov.cn/Portals/0/zhuanti/fazhan/%E8%BA%AB%E4%BB%BD%E8%AF%81GB11643-1999.pdf), [Korea's Ministry of the Interior announcement](https://www.mois.go.kr/frt/bbs/type002/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000205&nttId=78282) and [Canada's SIN guidance](https://www.canada.ca/en/employment-social-development/services/sin/reports/code-of-practice.html). Canada's public guide describes the identifier; the offline python-stdnum oracle supplies an additional implementation check for Luhn and reserved prefixes.

[Microsoft Presidio's entity list](https://presidio.dataprivacystack.org/supported_entities/) was read only to compare coverage. No recognizer code was copied. The independent [Python reference](../scripts/country_reference.py) expresses CPF with ascending weights, China with the MOD 11-2 recurrence, Verhoeff with rotations and reflections in D5, and Luhn with decimal digit sums. Go uses descending CPF weights, positional Chinese weights, Verhoeff tables and the subtract-nine Luhn form. [Lean references](../tests/lean/Countries.lean) generate arithmetic vectors for seven checksum families, including numeric and alphanumeric CNPJ. Lean checks D5 identity, the permutation's period and check-digit ranges; it does not prove that the Go parser implements those definitions or that a number was issued.

## Frozen evaluation

The generator uses different seeds and surrounding log templates for development and held data. Both 6,720-row files were prepared before detector implementation; [freeze metadata](../tests/testdata/countries-freeze.json) and the [manifest](../tests/testdata/countries-manifest.json) retain their hashes. Each kind has 96 generated values in bare, formatted and percent-encoded forms, plus rejected mutations, embedded identifiers, public order IDs and clean logs. RRN adds 32 labeled modern values with invalid legacy checks. Public-ID negatives deliberately share valid identity syntax, exposing the precision cost of retaining ambiguous values. The initial rules were evaluated before inspecting held results. Review later exposed an overlapping-SIN omission; its independent regression test drove the correction, and both frozen corpora were replayed unchanged. These committed rows are regression data after evaluation.

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

The checksum-pinned datasets in the [manifest](real-logs-manifest.json) combine LogHub system logs with web access, Kubernetes audit and CloudTrail logs; the [real-log page](real-logs.md) lists their sizes. Raw logs and sampled excerpts remain outside Git. The [real-log evidence](real-logs.md) records licenses, hashes and sample labels. Each dataset/kind stratum uses at most 40 deterministic sampled findings; FP/GB is count multiplied by the sampled false-positive fraction, divided by decimal GB. This is an estimate, not recall or a confidence bound. The LogHub held split has already been inspected during evaluation.

<!-- country-logs:start -->
| Kind | Dev findings | Dev sampled FP / sample | Dev estimated FP / GB | Held findings | Held sampled FP / sample | Held estimated FP / GB |
|---|---:|---|---:|---:|---|---:|
| br_cnpj | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| br_cpf | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| ca_sin | 15 | 15 / 15 | 110.3 | 14 | 14 / 14 | 134.8 |
| cn_resident_id | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| in_aadhaar | 0 | 0 / 0 | 0.0 | 648 | 40 / 40 | 6,237.9 |
| in_pan | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| kr_rrn | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| uk_nhs | 0 | 0 / 0 | 0.0 | 194 | 41 / 41 | 1,867.5 |
| uk_nino | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| us_itin | 0 | 0 / 0 | 0.0 | 0 | 0 / 0 | 0.0 |
| us_ssn | 165 | 73 / 73 | 1,213.2 | 43 | 43 / 43 | 413.9 |
<!-- country-logs:end -->

The sampled SSN matches are Android event times and lock identifiers, Linux inode/process values and BGL counters. SIN matches overlap those numeric fields, Zookeeper snapshot filenames and one OpenSSH hostname fragment. NHS matches are BGL epoch seconds. These are false positives for national identifiers even when a machine or user reference elsewhere on the same line could be sensitive. Zero findings for the remaining kinds only describes this corpus.

[Support maintenance](https://github.com/sponsors/nao1215).
