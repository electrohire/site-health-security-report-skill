<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Site Health & Security Report — an agent skill

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A daily (or weekly) health and security report for any website, produced
by an AI agent, graded A to F, in plain language an owner can act on.
This is a daily health and security report method designed by
ElectroHire, generalized to any stack, published as an open agent
skill.

**Status: pre-release, version 0.9.0.** The skill is public for review
and is being iterated against red teams and simulated stacks until a
complete verification round finds no issues. The first release will be
v1.0.0; versioning is semantic from that release, with a changelog
kept in Keep a Changelog format from that release on.

The report watches, every edition:

- **Traffic and reliability** — reachability, status-code mix, anomalies,
  scanner and probe traffic, segmented by host and client address.
- **SEO / AEO** — search and AI-crawler readiness scores, with a fallback
  chain so a checker outage never becomes a blank or an invented number.
- **Code safety** — vulnerable dependencies, code scanning (SAST), and
  secret scanning, on GitHub, GitLab, Bitbucket, Azure DevOps, or Gitea.
- **Perimeter** — TLS grade and certificate horizon, the six security
  headers (enforcing CSP, not report-only), email authentication
  (SPF/DMARC), and DDoS posture for the site **and** the API.
- **Privacy/AI spot checks** — controller named correctly, AI disclosure,
  cookie consent, a published data-request route.
- **Action** — three to five ranked recommendations, each with a named
  owner, and a follow-up line on last edition's recommendations.

## It does not assume your stack

The skill starts with a mandatory **stack intake**: edge provider, code
host, scanning tools actually in place, hosts and their roles, staging
setup, recipients, owners, sending route. The report is then produced
through the adapter for your stack:

| Layer | Supported |
|---|---|
| Edge / DDoS | Cloudflare · AWS CloudFront + WAF/Shield · Azure Front Door + WAF · Fastly · Akamai · Sucuri · other (generic contract, note required) · none (log-based, graded honestly) |
| Code host | GitHub · GitLab · Bitbucket · Azure DevOps · Gitea/Codeberg · other (generic contract, note required) |
| Scanning | Dependabot/CodeQL/secret scanning · GitLab SAST/DS/SD · pipeline fallbacks: Semgrep, CodeQL CLI (where licensed), gitleaks, Trivy, OSV-Scanner · commercial: Snyk, SonarQube, Mend, GitGuardian |
| Staging | Branch-staging on Cloudflare Pages · Vercel · Netlify · Azure Static Web Apps · AWS Amplify / S3+CloudFront |

Bitbucket has no native scanning; the skill says so and wires the
pipeline fallback stack instead of pretending. Full honesty rules are in
the skill itself.

## Two lessons from production are built in

1. **The burst rule.** A wall of 5xx errors is not automatically an
   outage. Segmented by host and client address, one real production
   "outage" turned out to be a single scanner probing an API side host.
   The skill classifies bursts mechanically before anyone writes the
   word *outage*, and the test suite carries the regression case.
2. **Gate before send.** Every edition passes a pre-send verification
   gate and an independent validation pass. Corrections still happen,
   openly, but a correction for a preventable error is treated as a
   process failure, not a routine.

## Quick start

1. Copy `skills/site-health-security-report/` into your agent's skills
   directory (per-agent paths: [docs/agent-integrations](docs/agent-integrations/)).
2. Ask your agent: *"Run the stack intake for the site health report."*
   Answer the eleven questions.
3. The agent saves your config from
   `skills/site-health-security-report/templates/config.example.json`.
4. Ask for the first edition, review it, then schedule it (the skill
   covers scheduling and exactly-once sending).

## Repository layout

```text
skills/site-health-security-report/
  SKILL.md            the skill itself
  references/         intake, grading, edge + code-host adapters,
                      scanning fallbacks, DDoS, staging, writing,
                      verification
  templates/          config (JSON + YAML), report, HTML email,
                      correction, AEE evidence ledger
  scripts/            site_health.py — stdlib-only deterministic tools
tests/                unit suite + scenario fixtures (stdlib unittest)
docs/                 why it works, stack selection, staging workflow,
                      agent integrations
specs/                the spec-kit package this repo was built from
aee/                  the AEE claim/evidence pack for the method
.github/              CI, issue + PR templates, Dependabot
```

## Run the tests

```bash
python3 -m unittest discover -s tests -v   # the full suite, no dependencies
```

## Documentation

- [Why each check exists, what it protects, costs and trade-offs](docs/why.md)
- [Choosing the ideal stack (and fixing a missing layer)](docs/stack-selection.md)
- [The branch-staging workflow](docs/staging-workflow.md)
- [Agent integrations](docs/agent-integrations/) — Codex, Meta Muse,
  Claude Code, Cursor, Windsurf, GitHub Copilot, Gemini CLI, Aider

## Built with spec-kit + AEE

The repository was specified before it was built: see
[`specs/001-site-health-report-skill/`](specs/001-site-health-report-skill/)
for the spec, plan, and task list, and [`aee/claims.md`](aee/claims.md)
for the claims the method makes, each with its falsifier and the
evidence that backs it.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities through
[SECURITY.md](SECURITY.md), never in a public issue.

## License

MIT. Copyright (c) 2026 ElectroHire Inc. Every source file carries SPDX
tags (`SPDX-License-Identifier: MIT`,
`SPDX-FileCopyrightText: 2026 ElectroHire Inc.`).
