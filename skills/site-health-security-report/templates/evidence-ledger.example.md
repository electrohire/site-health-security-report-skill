<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
AEE evidence ledger for one edition. Every claim in the report traces
to a record in the run's evidence folder; the falsifier states what
would prove the claim wrong. Copy per edition: evidence-ledger-<date>.md
-->
# Evidence ledger — {{date}} edition

| # | Claim (as printed) | Evidence record | Falsifier (what would disprove it) | Status |
|---|---|---|---|---|
| 1 | Requests were {{n}} on {{covering_date}} | `evidence/edge-traffic-{{date}}.json`, totals row | The same query re-run returns a different total | verified |
| 2 | Overall grade is {{overall}} | `evidence/findings-{{date}}.json` fed to `scripts/site_health.py grade` | Recomputing from the findings file yields another grade | verified |
| 3 | The 5xx burst was a scanner event, not an outage | `evidence/edge-burst-{{date}}.json` segmented by host and client address | Segmentation shows the primary host serving the errors to many addresses | verified |
| 4 | CSP is enforcing | `evidence/headers-{{date}}.json` from `scripts/site_health.py headers` | The response carries only a Report-Only header | verified |
| 5 | {{seo_score}} is today's SEO score | Checker results page, scan id {{seo_scan_ref}}, saved to `evidence/browser-results-{{date}}.txt` | The checker's history shows the id belongs to another day | verified |

Rules: a claim with no evidence record does not print. A claim whose
falsifier fires is corrected before sending, or the edition is held.
Summaries from helper agents are leads; the record in column 3 is the
source.
