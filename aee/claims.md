<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# AEE claims pack — the method's claims, falsifiers, and evidence

Applied Epistemic Engineering discipline: the skill makes claims. Each
claim here carries the observation that would falsify it and the
evidence on file. A claim whose falsifier fires is corrected in the
skill and in this pack, in the open.

| ID | Claim | Falsifier | Evidence | Verdict |
|---|---|---|---|---|
| C1 | The grading functions reproduce the production rubric: a healthy GitHub+Cloudflare day grades A; scanning-dark caps Security at C; a public exploit in production grades F. | Any scenario fixture grading differently in the suite. | `tests/fixtures.py` + the test modules (the full suite; count and status verified each round by the suite itself and CI). | supported |
| C2 | Report-only CSP is never counted as enforcing. | A headers fixture with only a Report-Only header returning "enforcing". | `TestHeaders.test_report_only_is_not_enforcing`. | supported |
| C3 | The burst rule separates a scanner event from a real outage on the same totals. | Either segmentation fixture classifying the other way. | `TestBurstRule` (5 tests). | supported |
| C4 | Bitbucket Cloud offers no native dependency, SAST, or secret scanning, so the skill's fallback stack is necessary there. | Atlassian shipping native scanners of any of the three kinds. | Stated as of 2026-11; the config validator rejects a Bitbucket "native" SAST claim (`TestConfigValidation.test_bitbucket_native_sast_claim_is_rejected`). Re-check at each release. | supported, time-boxed |
| C5 | The skill cannot silently run on an assumed stack: incomplete or unknown-stack configs fail validation. | A config missing intake fields, or naming an unknown provider, validating clean. | `TestConfigValidation` + `TestConfigHardening` + `TestScanningVocabulary`/`TestConfigCompleteness2` (24 config tests). | supported |
| C6 | A composed edition that disagrees with its findings file (any overall-grade occurrence, the anchored Sub-grades line, per-section grade lines, missing sections, an incomplete run not presented as incomplete) is caught before sending. Narrative figures are the pre-send gate's job, not the validator's. | A grade-mismatched or section-missing fixture passing `validate_report`. | `TestReportValidation` (3 tests). | supported |
| C7 | The report's value claim: owners act on graded, owned, daily findings more reliably than on raw dashboards. | Field reports from adopters showing editions unread or actions unowned over a month of use. | The original deployment: editions drove fixes (for example, CSP enforcement landed after standing as a named cause). Adopter evidence: none yet; claim is open. | partially supported, open |

| C8 | An edition whose findings contradict its configured stack, or whose sender/recipients were re-typed instead of copied from the config, fails validation: `check-run` validates config, findings, and report together, an outage requires the burst segmentation record inside the findings to classify as an outage, and a score requires its run identifier. | A contradictory triple passing `validate_run`, an asserted outage grading F without a record, or a score grading without its identifier. | `tests/test_round3.py` (the round-3 battery: cross-artifact, burst-record, provenance, vendor-scale, type-confusion tests), extended by the contradiction batteries in `tests/test_round12.py` and `tests/test_round13.py` (all three scanner kinds, evidence and assertion layers). | supported |

## Development record (pre-release)

Status: **pre-release** (the current minor version lives in the
repo's VERSION file and README). The repository is public for
review (https://github.com/electrohire/site-health-security-report-skill,
MIT, Copyright (c) 2026 ElectroHire Inc.), but nothing is released:
versioning restarts at v0.1.0 and increments by minor versions during
the pre-release iteration. The first release will be v1.0.0, only when
a complete verification round (red team plus full-run and
adversarial-agent simulations) returns zero findings and the owner
gives explicit permission; a Keep a Changelog changelog and semantic
versioning start at that release. Branch protection on main: 1
approving review required, stale reviews dismissed, force pushes and
deletions disabled (verified from the protection API). Topics set
(15). Red-team rounds and simulated stack combinations run against
every pre-release state until a complete round returns zero findings;
their findings are the regression batteries in tests/.
