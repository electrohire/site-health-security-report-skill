<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Verification, validation, sending, corrections

These controls exist because every one of them has caught a real error
in production use. A correction email for a preventable composition
error is a process failure; the gate is cheaper.

## Authorization before any send

The owner approves the first edition before it sends, and approves any
change to recipients, sending route, or schedule before it takes
effect. The signed-off config is the standing authorization for
scheduled editions under it; nothing outside it (a new recipient, a new
route, a one-off extra send) is authorized. A correction that changes a
grade needs the owner's approval before sending.

## Pre-send verification gate

After composing, before sending, re-read every headline figure in the
edition against the saved record it came from:

- grades against the rubric applied to the findings file;
- traffic totals against the edge analytics records;
- dependency and scanning counts against the scan records;
- scan grades (Observatory, SSL Labs, headers) against the saved scan
  outputs;
- every SEO/AEO figure against this run's checker record and its
  identifier;
- for any day with an error spike or an outage claim: the segmentation
  record exists, the burst classification was run on it, and the
  edition's traffic story (and the findings' `outage_confirmed`) match
  the classification. A figure can trace perfectly and still be the
  wrong story; this item checks the story.

A figure that cannot be traced is corrected from the record, or dropped
and stated as not available, before sending. The gate's result (figures
checked, corrected, dropped) is logged in the run log. Records are
checked for internal freshness: a file's name or existence is not
evidence; its internal date or requested window must match the covering
day.

## Independent validation

The edition's mechanical validation is `check-run` (config, findings,
and report together); it must pass before this pass begins. Then, a
second pass by an agent or person who did not compose the edition. A
solo operator who has no second agent or person available does not
claim independence that did not happen: they re-derive the edition from
the primary records in a separate pass and label the validation record
"self-validated, independence not available". The steps:

1. Re-derive totals, shares, and all grades from the primary records.
2. Confirm checker results first-hand on the checker's own pages
   (identifier, timestamp, latest-in-history position).
3. Take cross-edition comparisons from yesterday's saved records, never
   from yesterday's prose.
4. Render the email (dry run) and confirm the HTML and the plain-text
   part carry the same headline figures and grades; renderers that
   parse sections can silently drop content from one part.
5. Confirm all six legs are present, and every "not available" carries
   its reason.
6. Confirm the send log holds no entry for this edition's idempotency
   key, and the payload's recipients exactly equal the config's.

The validator writes a dated validation record (pass/fail per check,
with evidence pointers). The sender runs only on a full pass.

## Send discipline

- Exactly once: an idempotency key per edition (`report-<date>`,
  `correction-<date>`), checked against the send log before sending,
  matched on the key, never on the subject line (subjects embed the
  grade and can change between runs).
- Verify from the send record: the provider's accepted id, appended to
  the send log and read back. If the send succeeded but the log write
  failed, record the printed id first, before anything else; an
  unrecorded send gets re-sent when the idempotency window lapses.
- Backlog: a missed edition is sent before today's, marked as a late
  edition; a backlog older than one missed edition is surfaced for an owner
  decision instead of being sent automatically.
- No fallback route improvisation: if the configured route fails, the
  edition is saved, marked UNSENT, and surfaced with the reason.
  Switching accounts or routes mid-incident is how duplicates and
  wrong-sender sends happen.

## Corrections

A correction is a send like any other: corrected file, full gate and
validation re-run (`check-run --kind correction` against the corrected
findings), recipients copied from the config, its own
idempotency key, verified from its send-log line. The config the
correction validates against is the config version that governed the
corrected edition (kept per the amendment discipline in
stack-intake.md), not the current config: after a stack change, the
old edition's findings truthfully name the old stack's scanners.
State plainly what
was wrong, what the correct figure or reading is, whether the grade
changes, and what process fix prevents the repeat.
