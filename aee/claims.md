<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# AEE claims pack — the method's claims, falsifiers, and evidence

Applied Epistemic Engineering discipline: the skill makes claims. Each
claim here carries the observation that would falsify it and the
evidence on file. A claim whose falsifier fires is corrected in the
skill and in this pack, in the open (see CHANGELOG.md).

| ID | Claim | Falsifier | Evidence | Verdict |
|---|---|---|---|---|
| C1 | The grading functions reproduce the production rubric: a healthy GitHub+Cloudflare day grades A; scanning-dark caps Security at C; a public exploit in production grades F. | Any scenario fixture grading differently in the suite. | `tests/fixtures.py` + `tests/test_site_health.py` + `tests/test_hardening.py`, 63 tests green (2026-11-10 local run, after the red-team pass). | supported |
| C2 | Report-only CSP is never counted as enforcing. | A headers fixture with only a Report-Only header returning "enforcing". | `TestHeaders.test_report_only_is_not_enforcing`. | supported |
| C3 | The burst rule separates the 2026-11-10 scanner event from a real outage on the same totals. | Either segmentation fixture classifying the other way. | `TestBurstRule` (4 tests). | supported |
| C4 | Bitbucket Cloud offers no native dependency, SAST, or secret scanning, so the skill's fallback stack is necessary there. | Atlassian shipping native scanners of any of the three kinds. | Stated as of 2026-11; the config validator rejects a Bitbucket "native" SAST claim (`TestConfigValidation.test_bitbucket_native_sast_claim_is_rejected`). Re-check at each release. | supported, time-boxed |
| C5 | The skill cannot silently run on an assumed stack: incomplete or unknown-stack configs fail validation. | A config missing intake fields, or naming an unknown provider, validating clean. | `TestConfigValidation` + `TestConfigHardening` (13 config tests). | supported |
| C6 | A composed edition that disagrees with its findings file (overall grade, any sub-grade, missing sections, an ungraded leg not stated as not available) is caught before sending. | A grade-mismatched or section-missing fixture passing `validate_report`. | `TestReportValidation` (3 tests). | supported |
| C7 | The report's value claim: owners act on graded, owned, daily findings more reliably than on raw dashboards. | Field reports from adopters showing editions unread or actions unowned over a month of use. | The original: ElectroHire's editions drove fixes (CSP enforcement landed 2026-11-10 after standing as a named cause). Adopter evidence: none yet; claim is open. | partially supported, open |
