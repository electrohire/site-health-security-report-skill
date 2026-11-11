<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# The findings file (schema of record)

Each edition produces one findings file, `findings.json`, in its dated
evidence folder. It is the **grading subset** of the day's evidence:
exactly the fields `scripts/site_health.py` grades from. The report's
narrative figures (request totals, top paths and countries, scan
identifiers and timestamps, audit counts) live in the legs' raw evidence
records and are traced through the evidence ledger; they are not grading
inputs and do not belong in this file.

Types are strict and validated before grading. A string `"false"` where
a boolean belongs, a share above 1, or a score above 100 is an input
error, and grading refuses to run: a malformed findings file must never
manufacture a grade. Missing measurements in the traffic and security
legs are likewise errors. A leg whose *scores* could not be produced
(SEO/AEO) is recorded with null scores: the leg is then reported as not
available and the overall grade is flagged incomplete, never silently
computed as if the leg did not exist.

## traffic (all fields required)

| Field | Type | Meaning |
|---|---|---|
| `five_xx_share` | number 0–1 | Residual server-error share of requests, **after** burst segmentation (see grading.md) |
| `four_04_share` | number 0–1 | "Not found" share of requests |
| `outage_confirmed` | boolean | True only when the burst rule classifies the day as a primary-host outage and the primary host was actually down |
| `repeated_reliability_problems` | boolean, optional | True when error problems repeated across days (the report's run records are the evidence) |

## seo_aeo

| Field | Type | Meaning |
|---|---|---|
| `aeo_score` | number 0–100 or null | AI-readiness score from this run's scan (identifier and timestamp live in the evidence record) |
| `seo_score` | number 0–100 or null | SEO score from this run: the primary checker, or the labelled fallback (PageSpeed SEO category score, or the self-run audit converted as passed/15 × 100) |

## security (fields marked required must be measured, never omitted)

| Field | Type | Meaning |
|---|---|---|
| `critical` | int ≥ 0, required | Open critical dependency/code alerts across product repos |
| `high` | int ≥ 0, required | Open high-severity alerts |
| `medium`, `low` | int ≥ 0 | Backlog counts; reported, but they do not lower the grade by themselves |
| `code_scanning_on` | boolean, required | True only if code scanning actually ran on every product repo |
| `secret_scanning_on` | boolean, required | Same, for secret scanning |
| `secret_alerts_open` | int ≥ 0 | Open secret-scanning alerts |
| `critical_public_exploit_in_production` | boolean | The F condition |
| `csp` | `"enforcing"` / `"report-only"` / `"missing"`, required | From the header check, value-inspected |
| `observatory_grade` | letter (any case) or null | Mozilla Observatory |
| `ssl_grade` | letter (any case) or null | SSL Labs |
| `cert_days_left` | number or null | Negative means already expired |
| `dmarc` | `"reject"` / `"quarantine"` / `"none"` / `"missing"`, required | The domain's DMARC policy posture |
| `privacy_failures` | int ≥ 0 | Failing privacy/AI spot checks this run |
| `ci_blocked` | boolean | True when CI/CD cannot run at all (billing block, disabled pipelines) |

## The burst record

Segmentation figures are kept as their own small record and classified
with `site_health.py burst`: `total_errors`, `top_single_ip_errors`
(errors from the single busiest client address), `primary_host_errors`,
and `top_single_host_errors` (errors on the single busiest host, which
is what separates a side-host probe event from a distributed failure).
