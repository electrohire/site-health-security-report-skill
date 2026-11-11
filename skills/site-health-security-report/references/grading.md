<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Grading rubric (identical in every deployment)

Grades are computed by `scripts/site_health.py` from the edition's
findings file, so the grade is a function of the evidence, not of the
writer's mood. Overall grade = the lowest of the three sub-grades.

## Base bands

| Grade | Security alerts | SEO/AEO scores | Reliability |
|---|---|---|---|
| A | No critical or high open (a medium/low backlog does not by itself lower the grade) | 90+ | No 5xx problem |
| B | (the security leg has no B: it holds A until the first named cause caps it at C) | 80-89 | Minor issues only |
| C | Any high open | 70-79 | A noticeable error problem |
| D | Any critical open | 50-69 | Repeated reliability problems |
| F | Critical with a public exploit in production | Under 50 | Site down (primary host, per the burst rule) |

## Named downgrade causes (Security & code health)

Each of these, while true, is named in one line as a cause and caps the
Security sub-grade at C unless a worse band already applies:

- No edge/DDoS layer in front of the origin, or an edge with no WAF or
  equivalent application-layer protection verified (`edge_posture`).
- Code scanning dark on any product repository.
- Secret scanning dark, or a secret-scanning alert open.
- No enforcing Content-Security-Policy (report-only does not count).
- Mozilla Observatory grade D+ or worse (D+, D, D-, F).
- SSL Labs grade below B, or a certificate expiring in under 14 days.
- DMARC missing, or DMARC policy `p=none`.
- Any privacy/AI spot check failing (wrong controller named, no AI
  disclosure, no data-request route).
- CI/CD unable to run (billing block, disabled pipelines), because the
  security pipeline cannot run either.
- No verified backup of the site itself (`site_backups_verified`
  recorded false at intake or since).

## Traffic & reliability causes

Cadence: every share and count in this rubric is computed over the
edition's covering period (a day at daily cadence, a week at weekly).
An outage confirmed for any part of the covering period counts for
that edition.



- 5xx share of traffic: at or under 0.1% is normal noise; above that up
  to and including 0.5% is minor (B, and the cause line names the
  figures); over 0.5% up to 2% is a noticeable problem (C); over 2% or
  repeated problems across editions is repeated reliability trouble (D); a
  confirmed primary-host outage is F. An elevated 404 share behaves the
  same way: over 5% up to and including 10% is B; over 10% is C.
- Apply the burst rule first: traffic concentrated in one client address
  or on a non-primary host is a scanner/probe event. It is reported as a
  security-relevant event, and it does not set the reliability grade as
  an outage. A burst spread across hosts in proportion to their traffic
  classifies as "distributed" (an origin or region failure pattern): it
  is graded on volume, and it is neither a scanner event nor an
  automatic outage.
- Burst-to-grade procedure: (1) classify the burst from its four
  segmentation figures; (2) attribute the burst's errors to the event;
  (3) the findings file's `five_xx_share` is the residual, (the covering
  period's total 5xx minus the burst's 5xx) divided by the covering
  period's total requests (on an outage-classified day nothing is
  attributed away, so the share is the period's total share); the
  same attribution applies to `four_04_share` (the burst's 404s are
  removed the same way);
  (4) `outage_confirmed` is set true only when the classification is
  "outage" and the primary host was actually down. The thresholds, as
  the tool computes them (integer-exact): one client address at 60% or
  more of the errors, or one host at 60% or more while the primary host
  is under half, is a concentrated event; the primary host at 50% or
  more with no single address dominating is an outage; anything else is
  distributed. The segmentation record goes in the findings file as
  `traffic.burst`, and the grader enforces that the outage claim and
  the record agree; a record whose busiest-host count is below its
  primary-host count is rejected as a field swap.
- Elevated 404 share (over ~10% of traffic) is a noticeable error problem
  and is named, because it usually means broken links, a bad deploy, or
  scanning the site cannot absorb.

## Rules that keep grades honest

- A grade improves only on evidence from the current run, never because
  yesterday's problem was not mentioned today.
- A checker that produced no result contributes no score; the fallback
  chain runs, and the grade uses the fallback's band, labelled as such.
  The self-run audit converts to a score as passed/15 × 100, labelled
  "self-run on-page audit".
- If a leg still produces no score, it is graded as not available: the
  report says so, and the overall grade is presented as incomplete
  (computed from the graded legs only), never as a clean grade.
- Every downgrade names its cause in one line, in the edition, next to
  the grade.
