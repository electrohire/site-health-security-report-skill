<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Contributing

Thanks for helping. The bar for this repository is the bar the skill
teaches: evidence first, no invented claims, judgment calls covered by
tests.

1. Fork, branch from `main`, and keep changes focused.
2. Run `python3 -m unittest discover -s tests` before opening a PR.
   The suite is standard library only; keep it that way.
3. Changed a grade, threshold, classification, or a factual claim about
   a vendor? Add or update a test, and update `aee/claims.md` in the
   same PR. Vendor claims must name their source and their date; they
   age, and the claims pack says when each was last checked.
4. Every new file carries the SPDX header used by its neighbours.
5. Write docs in plain language, US English, and say what a thing
   protects and what it costs, not only how to run it.
