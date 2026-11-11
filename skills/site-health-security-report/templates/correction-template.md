<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
White-label correction template. The two headings and the Corrected
grades line are literal: the validator (check-run --kind correction)
requires them in this shape. Delete this comment before sending.
-->
Subject: Correction — {{brand.display_name}} {{cadence}} report — {{date_short}}: {{short_reason}}

Correction — {{brand.display_name}} {{cadence}} report — {{date}} (covering {{covering_text}})

## What was wrong

{{The figure or reading that was wrong, and what the edition said, in
one plain paragraph.}}

## What is correct

{{What is actually true, with the source that establishes it.}}

Corrected grades: Traffic & reliability {{traffic_grade}} · SEO/AEO {{seo_grade}} · Security & code health {{security_grade}}. (When a leg is ungraded in the corrected findings, put "not available" in its slot and append " (incomplete: <leg> not available)" to this line.) The corrected overall grade is {{corrected_overall}} (was {{sent_overall}}).

{{Which recommendations from the original edition are withdrawn,
replaced, or stand.}}

{{Any post-report improvement, marked as post-report so it is not
backdated into the covering day's grade.}}

We are sorry for the error. The process fix on our side is {{process_fix}}.
