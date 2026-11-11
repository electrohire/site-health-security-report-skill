<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Plan 001 — build approach

1. **Skill first.** `SKILL.md` carries the method and the hard rules;
   references carry depth (intake, grading, adapters, fallbacks, DDoS,
   staging, writing, verification). Anything an agent needs at 8 AM
   with no human awake must be reachable from `SKILL.md` in two hops.
2. **Deterministic core.** Judgment calls that history shows agents get
   wrong (grades, CSP posture, outage vs scanner) are functions in a
   stdlib-only Python module, so they are identical across runs and
   agents, and testable without network access.
3. **Templates over prose.** Report, email, correction, config, and the
   evidence ledger are templates filled from records; the validator
   checks a composed edition against the findings that produced it.
4. **Tests as scenarios.** Fixtures model real customer shapes (healthy
   GitHub+Cloudflare; Bitbucket+AWS with scanning dark; the scanner
   burst day; an exploited production dependency) so a regression in
   judgment shows up as a failing scenario, not a surprise email.
5. **Adversarial pass.** Before release, independent agents apply the
   skill to simulated stacks and a red team attacks it for assumption
   leaks, invented-number paths, and unsafe actions; findings are fixed
   or documented as limits, and the claims pack (`aee/claims.md`) is
   updated to match.
6. **Publish last.** The public repository is created only after the
   suite passes and the adversarial pass closes; branch protection and
   CI are part of the release checklist, verified from the API after
   being set.
