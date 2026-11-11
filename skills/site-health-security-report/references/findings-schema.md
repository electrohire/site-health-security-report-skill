<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# The findings file (schema of record)

Each edition produces one findings file, `findings.json`, in its dated
evidence folder. It is the **grading subset** of the covering period's
evidence (the period is a day at daily cadence, a week at weekly):
exactly the fields `scripts/site_health.py` grades from. The report's
narrative figures (request totals, top paths and countries, scan
identifiers and timestamps, audit counts) live in the legs' raw evidence
records and are traced through the evidence ledger; they are not grading
inputs and do not belong in this file.

Types are strict and validated before grading. A string `"false"` where
a boolean belongs, a share above 1, or a score above 100 is an input
error, and grading refuses to run: a malformed findings file must never
manufacture a grade. Required traffic and security fields must be
present (per-field rules below say which may be null and what null
means). A leg whose *scores* could not be produced (SEO/AEO) is
recorded with null scores: the leg is then reported as not available
and the overall grade is flagged incomplete, never silently computed as
if the leg did not exist. NaN and Infinity are rejected at load: they
are not measurements.

## traffic (all fields required)

| Field | Type | Meaning |
|---|---|---|
| `five_xx_share` | number 0–1 | Residual server-error share of requests, **after** burst segmentation (see grading.md) |
| `four_04_share` | number 0–1 | "Not found" share of requests |
| `outage_confirmed` | boolean | True only when the burst rule classifies the day as a primary-host outage and the primary host was actually down |
| `burst` | object, required when a burst was segmented | The segmentation record (`total_errors`, `top_single_ip_errors`, `primary_host_errors`, `top_single_host_errors`). The grader classifies it and requires the classification to agree with `outage_confirmed`; an outage claim without the record is an input error |
| `repeated_reliability_problems` | boolean, optional | True when the residual (post-segmentation) share exceeded the B band in at least 2 of the last 7 editions (the run records are the evidence; an outage day counts, a reclassified burst does not) |

## seo_aeo

| Field | Type | Meaning |
|---|---|---|
| `aeo_score` | number 0–100 or null | AI-readiness score from this run's scan |
| `aeo_scan_id` | string, required when `aeo_score` is present | This run's checker run identifier (the pre-send gate re-reads it against the checker record; a score carried over from a previous day has no identifier for today and must be recorded null instead) |
| `seo_score` | number 0–100 or null | SEO score from this run: the primary checker, or the labelled fallback (PageSpeed SEO category score, or the self-run audit converted as passed/15 × 100) |
| `seo_scan_id` | string, required when `seo_score` is present | This run's identifier for the score actually used (checker run id, PageSpeed run timestamp, or audit run id) |

Scanner severity mapping (when any scanner's severities must be
folded into the counts — a fallback scanner's vocabulary, or a native
scanner reporting levels beyond the four, such as GitLab's Info and
Unknown): scanner "critical"/blocker findings count as
`critical` only when they are exploitable in production as shipped;
otherwise map error/blocker to `high`, warning to `medium`, info/note
to `low`. Findings the scanner itself marks Unknown (no severity
assigned) are excluded from the counts and disclosed in the report
narrative and the derivation record. Record the mapping used in the
evidence record. When no
dependency tooling has run at all (not even the language-native audit),
record `critical` and `high` as null: the run grades incomplete with
the cause named, rather than inventing a zero.

## security (fields marked required must be measured, never omitted)

| Field | Type | Meaning |
|---|---|---|
| `critical` | int ≥ 0 or null, required | Open critical dependency/code alerts across product repos; null only when no scanner ran and the count is not measured (run grades incomplete) |
| `high` | int ≥ 0 or null, required | Open high-severity alerts; null under the same rule as `critical` |
| `medium`, `low` | int ≥ 0 | Backlog counts; reported, but they do not lower the grade by themselves |
| `code_scanning_on` | boolean, required | True only if code scanning actually ran on every product repo |
| `secret_scanning_on` | boolean, required | Same, for secret scanning |
| `scanners_used` | object | The scanner that actually produced each kind's counts, by config vocabulary name (`dependencies` / `sast` / `secrets`). `check-run` requires it to name the configured scanner for every kind that carries evidence (the `*_on` flag for sast/secrets, measured alert counts for dependencies): a fallback's output is read as the fallback's, never under the native scanner's name |
| `secret_alerts_open` | int ≥ 0 | Open secret-scanning alerts |
| `critical_public_exploit_in_production` | boolean | The F condition |
| `csp` | `"enforcing"` / `"report-only"` / `"missing"`, required | From the header check, value-inspected |
| `observatory_grade` | letter (any case) or null | Mozilla Observatory |
| `ssl_grade` | letter (any case) or null | SSL Labs |
| `cert_days_left` | number or null | Negative means already expired |
| `dmarc` | `"reject"` / `"quarantine"` / `"none"` / `"missing"`, required | The domain's DMARC policy posture |
| `privacy_failures` | int ≥ 0 | Failing privacy/AI spot checks this run |
| `ci_blocked` | boolean | True when CI/CD cannot run at all (billing block, disabled pipelines) |
| `edge_posture` | `"protected"` / `"cdn-only"` / `"none"`, required | `protected`: an edge is in front AND WAF or equivalent application-layer protection is verified **in block mode** (a WAF running in count/log-only mode is `cdn-only` until block mode is verified). `cdn-only`: an edge is present but no such protection is verified. `none`: no edge in front of the origin. `cdn-only` and `none` each cap Security at C with the cause named |

Enum tolerance: `csp` also accepts `report_only`; `dmarc` also accepts a
raw DMARC record (the tool reads its `p=` policy). Observatory grades
use the vendor's real scale (A+ through F, with plus/minus grades);
SSL Labs grades likewise (A+ through F, plus E, T, M). A numeric score
in those fields is an input error. If Observatory, SSL Labs, or the
certificate check produced no result, record null: the run is then
flagged incomplete, and the report says the item was not available
rather than silently grading it clean.

Config-to-findings mapping: a config whose scanning names `"none"` for a
scan type produces findings with the matching `code_scanning_on` /
`secret_scanning_on` set false. The config names what is set up; the
findings record what actually ran and was read. `check-run` enforces
this mapping mechanically (and the edge equivalent), so a findings file
that contradicts the configured stack fails validation.

## The burst record

Segmentation figures are kept as their own small record and classified
with `site_health.py burst`: `total_errors`, `top_single_ip_errors`
(errors from the single busiest client address), `primary_host_errors`,
and `top_single_host_errors` (errors on the single busiest host, which
is what separates a side-host probe event from a distributed failure).
