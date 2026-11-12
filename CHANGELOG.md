<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Round 39 (post-release red team, 2026-11-12) fixes and stack-proof
work; not yet released — a release is stamped only on the owner's
explicit permission.

### Added

- Netlify, Vercel, and Bunny as first-class edge providers, with
  adapter starting points, joining Cloudflare, CloudFront, Azure
  Front Door, Fastly, Akamai, and Sucuri.
- A per-stack simulation suite (tests/test_stack_sims.py): every
  edge × code-host combination the validator accepts is exercised
  end-to-end through the real CLI (validate-config, grade, burst,
  check-run) against a simulated deployment on disk, and every
  host's impossible-scanner claims are rejected in simulation.
- `validate-email`: the HTML email part is now mechanically
  validated against the findings, like the text part.
- Grype (dependencies) and Checkov (SAST) are recordable scanners,
  matching the scanning-fallbacks table that already recommended
  them.

### Fixed

- Duplicate keys in a JSON config/findings file are an input error;
  they previously resolved silently last-wins and could manufacture
  grades.
- A hostile Strict-Transport-Security max-age with thousands of
  digits crashed the header check with a traceback; the zero test no
  longer converts with `int()`.
- `classification_pending`, `compromise_confirmed`, and
  `outage_note` are presence-strict: a falsy mistype (0, "", null)
  is an input error, never a silent `false`.
- A residual 5xx share above the B band with no burst segmentation
  record now leaves the traffic leg ungraded (incomplete) instead of
  grading as a complete measurement.
- Scanner identity is enforced for inactive kinds too: findings
  naming a different scanner than the config are a check-run
  problem even when that kind was dark this edition.
- Corrections are recipient-checked: a correction naming any email
  address outside the configured sender and recipients fails
  check-run. Correction section headings are checked against the
  corrected grades, and an incomplete corrected grade must carry
  the template's "(incomplete: <leg> not available)" suffix.
- Prose grade forms ("overall grade of A", "grade was A") are
  checked like the anchored forms; fenced example blocks no longer
  satisfy an edition's grade apparatus or header.
- The Scanners of record line: a denied attribution ("was not
  performed by X") no longer counts as X's credit (and an honest
  denial is no longer flagged as a credit on a 'none' kind), and
  crediting only the role phrase ("by Dependency Scanning") names
  no scanner.
- Renovate can no longer be recorded as the dependencies scanner
  (it updates dependencies; it does not detect vulnerabilities),
  and SonarQube is no longer accepted as a dependency scanner —
  both match what the adapters have always said.
- 'other' providers reject placeholder notes ('.', 'unknown',
  'tbd', ...); hostnames and repository paths are shape-checked,
  and the primary host cannot be listed as its own side host.
- Docs: the GitLab severity-mapping rule is stated as one
  unambiguous procedure, GitLab artifact counting rules are
  specified, the Fastly adapter names its geo field and no-stream
  disposition, and the AEE claims pack no longer describes the
  released skill as pre-release.

## [1.0.0] - 2026-11-11

First release. The skill was developed in public as a pre-release
(0.1.0 to 0.35.0) and iterated against independent red teams and
full-run simulations on simulated stacks until a complete
verification round returned zero findings (round 38).

### Added

- The `site-health-security-report` skill: a graded health and
  security report for a website (traffic and errors, SEO/AEO
  scores, dependency, SAST, and secret scanning, plus header,
  certificate, and privacy-notice checks) at a daily, weekly, or
  monthly cadence, with evidence behind every figure, a pre-send
  verification gate, independent validation, and owner-approved
  sending.
- Mandatory stack intake: twelve questions, the answers recorded
  as the deployment's signed-off config; no vendor is ever assumed.
- Adapters for the edge providers (Cloudflare, AWS CloudFront,
  Azure Front Door, Fastly, Akamai/Sucuri, and a generic contract)
  and the code hosts (GitHub, GitLab, Bitbucket, Azure DevOps,
  Gitea/Codeberg, and a generic contract), plus scanning fallbacks
  (OSV-Scanner, Semgrep, gitleaks) for hosts without native
  scanning, and DDoS guidance with stack-selection costs.
- A stdlib-only companion CLI (`site_health.py`): header checks,
  grading identical to the production rubric, the burst classifier,
  and `check-run`, which validates a config, its findings, and the
  composed report together and recomputes every grade.
- Incident notes for F grades, confirmed outages, confirmed
  compromises, and exploited critical vulnerabilities, with a
  compromise-response minimum; a corrections discipline; multiple
  deployments with cross-deployment non-disclosure; operator
  handover, change-of-owner, and loss-recovery procedures.
- White-label report templates (plain text and HTML), config
  examples in JSON and YAML, pipeline examples for Bitbucket,
  Azure DevOps, and Gitea, issue and pull request templates, and
  agent integration guides for Codex, Muse, Claude Code,
  Cursor, Windsurf, Copilot, Gemini CLI, and Aider.
- A 265-test unit suite (stdlib only) covering the grading core,
  the validator, and every hardening round's regressions.
- Defect reporting, built in: the README's "Reporting bugs"
  section and the skill's own "Defects in this skill" rule
  instruct every agent using the skill to file a defect in this
  repository the moment one is found, so every issue is recorded
  for triage; the maintainers check the repository's issues
  daily.
- Update checks, built in: the skill's "Keeping the skill
  current" rule has the agent check for a newer release once
  per edition, at the report's own cadence, and surface it to
  the owner for an approved, between-editions adoption, never a
  silent or mid-run update.

[1.0.0]: https://github.com/electrohire/site-health-security-report-skill/releases/tag/v1.0.0
