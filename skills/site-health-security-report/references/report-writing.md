<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Writing the report

## Voice and shape

Plain language for busy owners. Headline grade and a one-line summary
first, then the sections of `templates/report-template.md`. Numbers
always carry a comparison (yesterday, the 7-day average, or the last
edition). Name every HTTP status code in plain English at first use
("404, the page does not exist"). No raw dumps, no framework scores
without a sentence saying what they mean.

Non-scored checker tips are reported as tips, never as failed items. A
scan result the tooling cannot name is stated once as a standing
unknown with the date first observed, not re-narrated daily.

## Source discipline

- Compose only from this run's saved evidence records. A sub-checker's
  or a helper agent's summary is a lead to verify, never a source; when
  a summary and a record disagree, the record governs and the conflict
  is resolved before composing, never after sending.
- Every score carries this run's identifier (scan id, report id, or
  timestamp). A previous day's score is never presented as today's; if
  no new scan could run, the section says so and uses the fallback
  chain, labelled.
- Fallback chain for SEO: primary checker, then PageSpeed Insights,
  then the self-run audit. Never present a fallback number as the
  primary checker's number. PageSpeed mechanics: use the **SEO category
  score** from the PageSpeed Insights report for the exact audited URL,
  and record the report URL and timestamp as this run's identifier.
  The self-run audit converts to a score as passed/15 x 100 and is
  labelled "self-run on-page audit" wherever it is used.

## The self-run on-page audit (15 checks)

HTTPS on; title present and 10 to 70 characters; meta description
present and 50 to 200 characters; exactly one canonical tag; meta
robots sane; viewport set; exactly one H1; no skipped heading levels;
image alt coverage at least 70%; internal links present; robots.txt,
sitemap.xml, and llms.txt reachable; page weight sane; response time
measured. Report as "self-run on-page audit: N of 15".

## Recommendations

Three to five, ranked by impact, each with a named owner from the
config. A recommendation that names no owner is a wish. When the
owner is also the operator (a solo deployment), a recommendation
carries the procedure in plain steps: where to go, what to click,
back up first where the change can break the site, what to check
afterwards, and what to do if it breaks. The tool's own grade-cause
strings are glossed into plain language in the edition, never
printed raw at a non-technical reader. Example: the tool's "no
verified backup of the site itself" becomes "we do not have a
backup of the website that we know can be restored, so if the
site broke badly we might not be able to bring it back."
Close the loop:
each edition states what happened to last edition's recommendations,
from evidence, one line per item in the Follow-up block, with one of
five outcomes: done, in progress, no movement, withdrawn (by a
correction — name its date), or declined (the owner decided against
it — record the decision and its date; a declined item leaves the
chain and is not re-issued). An item completed as a step inside a
later edition's recommendation is reported done in that edition's
follow-up block with a cross-reference to the procedure that
completed it. The block sits after the new
recommendations in the template layout; within the block, last
edition's items come first and nothing new is added there. An
item reported "no movement" is re-issued in the new
recommendations until it is done or withdrawn, so a stalled item
never silently drops out of the chain. The same applies to an
item reported "in progress": it stays in the new recommendations
until it is done or withdrawn, so an open item never lives only
in the follow-up block.

A straddling edition (a stack amendment mid-period) composes its
traffic figures from both sources: additive counts (requests,
errors, per-status counts) sum across the switch; figures that
cannot be merged, unique visitors above all, are printed as not
available with the reason, never summed. The next edition's
comparison line notes the break.

Comparisons, defined (round 12, cadence-corrected round 14):
comparisons pair like with like, in covering-period units. Where an
edition was corrected, its corrected figures are the comparison
inputs everywhere (previous-period figures and averages alike),
never the as-sent ones. The
Requests figure (the covering period's total) compares against the
previous covering period's total, and the baseline average is the
mean of the daily request totals over the previous seven covering
days, rounded to the nearest whole request (the same rounding
applies to a weekly edition's per-day figures) — for a daily deployment
that is the previous seven editions; for a weekly deployment it is
the previous edition's covering week, and the line prints it as a
per-day figure beside the week's own daily average, never as a
"7-day average" of edition totals. With less history it is the mean
of the covering days available, and the template line says so.
Unique visitors and page views compare against the previous edition
("yesterday" at daily cadence, "last week" at weekly, "last month"
at monthly). Dependency
totals compare against the previous edition —
except the first edition after a scanner change: its counts are not
like-for-like with the old scanner's, so the edition prints them with
an explicit "the scanner changed, not the code" note in WHAT CHANGED
and beside the counts, and the comparison chain restarts from that
edition. The same rule governs any leg source whose ruler changes —
a checker that revises its scoring, a platform that re-bases its
scale: the first edition on the new ruler prints its figures with a
"the ruler changed, not the site" note, comparisons against the old
ruler are not drawn, and that leg's comparison chain restarts from
that edition. When a headline series (a score, an error share, an alert
count, or a traffic total such as requests, uniques, or page views)
has moved in the same direction in at least 3 successive
edition-to-edition comparisons, WHAT CHANGED names the trend and
its span, even when no single edition's move is large: a slow
decline is a fact of the run, not of any one day.

Standing items live in the config's `standing_items` and in the
template's standing line. When an edition's own records verify a
standing item closed, the edition reports the closure and the config
entry is annotated `closed <date>` — annotated, never deleted, so the
history survives. A same-day correction is sent before that day's
edition, so the edition can report corrected facts in the past tense.

The self-run technical audit runs every edition and its line prints
every edition as a spot check; it is the SEO score source only when
both the checker and PageSpeed returned nothing for the covering
period, and the edition labels it as the source only then.

## First editions and clean editions

- First edition: "WHAT CHANGED SINCE THE LAST REPORT" reads "first
  edition: no previous report", the follow-up block reads "none (first
  edition)", and no comparison figures appear anywhere.
- A leg graded A carries no "Why a" cause line; the template prints
  "no downgrade causes" there instead. Cause lines exist only for
  grades below A, and the grading tool returns them.
- On an all-clean edition, recommendations are maintenance, honestly
  labelled: backlog burn-down (the medium/low counts), upcoming
  expiries, the next scheduled rotation. If there is genuinely nothing,
  say "no new recommendations; standing items continue" rather than
  inventing work.

## Display names for the template headings

`{{edge_name}}` (traffic heading) and `{{code_host_name}}` (security
heading) come from the config, title-cased for the heading style your
brand uses: cloudflare → CLOUDFLARE; aws-cloudfront → AWS CLOUDFRONT;
azure-front-door → AZURE FRONT DOOR; fastly → FASTLY; akamai → AKAMAI;
sucuri → SUCURI; other → the provider named in the config notes;
none → SERVER LOGS (NO EDGE). Code hosts likewise (github → GITHUB,
gitlab → GITLAB, bitbucket → BITBUCKET, azure-devops → AZURE DEVOPS,
gitea → GITEA, codeberg → CODEBERG, other → the host named in the
notes).
