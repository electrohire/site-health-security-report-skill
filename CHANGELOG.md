<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/electrohire/site-health-security-report-skill/releases/tag/v1.0.0
