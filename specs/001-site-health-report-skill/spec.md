<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Spec 001 — Site Health & Security Report skill

## Problem

Small web businesses learn their site is down, de-indexed, vulnerable,
or leaking secrets from customers, attackers, or a diligence call, in
that order. Monitoring exists, but it is fragmented per vendor, ungraded,
unowned, and unread. The ElectroHire daily report solved this for one
company on one stack (Cloudflare + GitHub). Other stacks, notably
Bitbucket and AWS, had no equivalent an agent could run.

## Goal

An open, white-label agent skill that produces the same graded daily
report on any common stack, with the production lessons of the original
encoded as mechanical rules and tests.

## Functional requirements

- FR-1: The skill requires a stack intake before any report; unknown
  fields are asked, never assumed. (Config validator enforces.)
- FR-2: Six gather legs (traffic, SEO/AEO, code-host security, standing
  items, public security scans, privacy/AI spot checks); a leg that
  cannot run is reported as not available with its reason.
- FR-3: Adapters for Cloudflare, CloudFront+WAF/Shield, Azure Front
  Door, Fastly, and no-edge log analysis; for GitHub, GitLab, Bitbucket,
  Azure DevOps, and Gitea.
- FR-4: Where a host lacks native scanning (Bitbucket), the skill
  specifies a pipeline fallback stack and grades its coverage honestly.
- FR-5: A to F grading, overall and three sub-grades, computed
  deterministically from a findings file; every downgrade names its
  cause.
- FR-6: The burst rule: no outage call without per-host and per-address
  segmentation; a helper function makes the call and a regression test
  carries the 2026-11-10 case.
- FR-7: Pre-send verification gate plus an independent validation pass;
  exactly-once sending with idempotency keys and send-log verification;
  corrections follow the same controls.
- FR-8: White-label templates (report, HTML email, correction, evidence
  ledger, config in JSON and YAML) driven entirely by the config.
- FR-9: The branch-staging workflow used by the ElectroHire beta site
  and axiovexsystems.com is documented as the recommended staging
  approach, including guard files and visual verification.
- FR-10: DDoS guidance covers the site and the API, explains what each
  control protects, and states costs and trade-offs per provider.
- FR-11: Integration guides for at least Codex, Meta Muse, Claude Code,
  Cursor, Windsurf, Copilot, Gemini CLI, and Aider.
- FR-12: A stdlib-only unit suite covers grading, headers (enforcing vs
  report-only CSP), burst classification, config validation (including
  the Bitbucket native-scanning rejection), and report validation.
- FR-13: The repository ships with an MIT license, SPDX attribution,
  issue and PR templates, CI running the suite, and branch protection
  on the default branch.

## Non-goals

- Performing the fixes the report recommends (the skill reports and
  grades; remediation is the customer's workflow).
- A hosted service, a dashboard product, or data collection of any kind.
- Replacing a compliance audit; the privacy leg is spot checks and is
  labelled as such.
