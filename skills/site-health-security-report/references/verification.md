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
route, a one-off extra send) is authorized, with one exception stated
here: the incident note. When an edition's findings confirm an outage,
an F grade, a confirmed compromise of the site, or a critical
vulnerability under active exploitation in
the product (a platform component counts), a short incident note to
the config's recipients,
through the config's sending route, is authorized by the same
sign-off. It carries the idempotency key `incident-<date>` and a
send-log line like any send; it is a note, not an edition, so it needs
no gate or validation, and its facts come from the day's saved
records. Its content: what happened, the evidence for it, and what
is being done — and for a solo deployment, the plain-step procedure
to act on it the same day, under the same rule as edition
recommendations. The trigger is the event itself, confirmed by the
day's saved records; it does not wait for an edition to be composed.
The next edition reports it. A correction that changes a
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
  the classification — including that the findings' `five_xx_share` is
  the post-segmentation residual (grading.md's burst procedure, step
  3), not the raw zone-wide share. A figure can trace perfectly and
  still be the wrong story; this item checks the story.

A figure that cannot be traced is corrected from the record, or dropped
and stated as not available, before sending. The gate's result (figures
checked, corrected, dropped) is logged in the run log. Records are
checked for internal freshness: a file's name or existence is not
evidence; its internal date or requested window must match the covering
period.

One disposition the gate needs in advance: for an error spike whose
segmentation is not yet available at send time, the edition sends on
schedule with the spike reported as an error spike, classification
pending. The findings carry `classification_pending: true` and no
burst record; the traffic leg is then not graded and the overall is
incomplete, because the only share that exists is the raw one and
grading it as if it were the residual is the failure this rule
exists to prevent. When the segmentation lands, the flag clears, the
edition is graded on the record, and a correction follows the same
day if the story changes. Holding the edition silently is not an
option.

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
3. Take cross-edition comparisons from the previous edition's saved
   records, never from its prose.
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
  grade and can change between runs). The incident note follows the
  same discipline with the key `incident-<date>`: check the log for
  it before sending, and verify it from the send record after.
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

## Backup and recovery

Two loss grades: if the off-machine copies survive, recovery is
restore, verify the restored config against the sent editions'
headers, and obtain the owner's re-approval — the field-by-field
reconstruction below is for the worse case, where the copies are
lost too.

The config is the standing send authorization and the evidence store
is the method's memory; both are single local files unless the
operator keeps copies elsewhere. Keep a copy of the config (the live
file and its versioned history) and of the send log on a second
machine or in the code-host account. The copies carry credential
locations, never values, and are stored with the same care as the
originals.

If they are lost anyway, recovery is a procedure, not an
improvisation:

1. Nothing sends until the config is re-established and the owner
   re-approves it. The standing authorization does not survive the
   loss of the signed-off config; re-approval re-establishes it.
2. Reconstruct the config field by field: the sent editions' headers
   and bodies recover the report-facing fields (sender, recipients,
   route, brand, schedule, edge, primary host); live account reads
   recover repositories, side hosts, and scanner enablement (which is
   re-verified through the adapter read paths, as at sign-off);
   credential locations are unrecoverable by design — re-issue the
   read credentials and record their new locations; process facts no
   record carries (the staging promotion path) are restated by the
   owner. Mark in the run log which fields are recovered, which are
   replaced, and which are owner-restated.
3. Rebuild the send log from the sending provider's own list of
   accepted sends (ids and idempotency keys), never from a
   sent-items folder, and verify the edition history is continuous
   (no missing editions) before resuming: a gap silently corrupts
   the averages, the follow-up chain, and standing-item history.
4. Rebuild standing items from the editions' standing lines, with
   closures annotated as usual.
5. Where saved records are gone, one disclosed exception applies:
   cross-edition comparisons and follow-up states may be taken from
   the sent editions' printed figures, stated in the validation
   record and the evidence ledger. Corrected figures govern later
   averages. A burst edition's findings cannot be fully re-derived
   (its segmentation record is not printed in full); a correction
   that needs it says so.
6. An edition sent late the same day says so in WHAT CHANGED; the
   covering period is not skipped.

## Compromise response (minimum)

The report detects vulnerabilities; it does not detect compromise.
When a compromise is confirmed (by the owner, the host, or the
platform), it is recorded as a standing item and in findings
(`compromise_confirmed`), and the response minimum is:

1. Preserve before touching: download the current backup and the
   available logs first — a suspension or cleanup can take them
   away, and the entry-point evidence lives in them.
2. Rotate every credential the compromise could have reached:
   platform admin, hosting account, database, edge, and the sending
   account.
3. Restore from a point that predates the earliest compromise
   evidence, not the newest backup; a backup taken inside the
   compromise window restores the compromise.
4. After the restore, re-read the platform versions and re-run the
   edition's legs; the item closes on that evidence, or by the
   owner's recorded decision where no leg can produce the evidence
   (see the standing-item rule in stack-intake.md).

## Operator handover

The standing authorization attaches to the owner and the signed-off
config, not to the operator: a change of operator alone is not a
first edition, a config change, or an amendment, and editions may
continue under it. The handover is still a recorded event:

1. What transfers: the config and its versioned history, the evidence
   store, the send log, the credential locations, the off-machine
   copies (whose custodian is named), and the open standing items.
2. The incoming operator validates the inherited config, re-verifies
   each scanner's existence through its adapter read path, and
   checks send-log continuity before their first edition.
3. The owner is told the operator has changed, and the handover is
   recorded in the run log.
4. End of service: the departing operator's access to the vault
   entries, the sending account, and the code-host token is revoked
   or rotated at the handover; the incoming operator confirms the
   rotation in their first editions' run records.

## Corrections

A correction is a send like any other: corrected file, full gate and
validation re-run (`check-run --kind correction` against the corrected
findings, saved as `findings-corrected.json` beside the as-sent
`findings.json`, which stands unmodified), recipients copied from the
config, its own idempotency key, verified from its send-log line. A
correction's own outcomes (its process fix, any commitment it made)
are reported in the next edition's follow-up block as an extra,
explicitly labelled line; that line also restates any recommendation
the correction withdrew, in its outcome form ("withdrawn (by the
correction of <date>)"), wherever in the chain the item originated. The config the
correction validates against is the config version that governed the
corrected edition (kept per the amendment discipline in
stack-intake.md), not the current config: after a stack change, the
old edition's findings truthfully name the old stack's scanners.
State plainly what
was wrong, what the correct figure or reading is, whether the grade
changes, and what process fix prevents the repeat.
