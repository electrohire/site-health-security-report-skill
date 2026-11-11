<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Choosing the ideal stack (when something is missing)

The skill runs on whatever the customer has. When a layer is absent,
the report recommends from this page, in the open, with prices and
trade-offs. Prices are 2026 list-price shapes, not quotes; verify at
purchase time.

## The reference stack (what "ideal" looks like for a small web business)

| Layer | First recommendation | Why |
|---|---|---|
| Edge / DDoS | Cloudflare (free, then Pro) | Unmetered L3/4 mitigation, the DDoS managed rulesets, and a small free managed WAF ruleset on the free tier (the full managed WAF is a paid tier); per-host and per-address analytics good enough for the burst rule; the cheapest correct answer for most sites. |
| Code host | GitHub | Dependabot, CodeQL, and secret scanning are built in; free on public repos; the report's richest adapter. |
| Scanning (private repos) | GitHub Advanced Security, or the free pipeline stack | GHAS if budget allows; Semgrep + gitleaks + OSV-Scanner if it does not. Coverage is graded, not brand. |
| Hosting with staging | Cloudflare Pages, Vercel, or Netlify | Branch deployments make the staging workflow nearly free. |
| Sending | A dedicated sending service on a verified subdomain (Resend, SES, SendGrid) | Keeps report and product mail reputation separate from the corporate mailbox, and produces a verifiable send record. |

## If the customer is AWS-first

CloudFront + AWS WAF + Shield Standard covers the edge; keep the origin
in private subnets or restrict it to CloudFront prefixes. Scanning is
unchanged (it lives at the code host or in CI). Watch the WAF
per-request bill under attack traffic; set budget alarms. This stack is
fully supported by the skill's adapters and is the right answer when
the team already runs on AWS.

## If the customer is Azure-first

Azure Front Door + WAF covers the edge; price Azure DDoS Protection
before assuming it (its flat cost surprises small sites, and a
Cloudflare front is sometimes the honest recommendation even in an
Azure shop). Code in Azure DevOps needs GHAzDO or the pipeline stack
for scanning; code in GitHub changes nothing.

## If the customer is on Bitbucket

Keep Bitbucket if the team is happy; add the pipeline fallback stack
(Semgrep, gitleaks, OSV-Scanner or Trivy, artifacts retained 35 days)
and the report reads it as full coverage. Add Snyk or SonarQube Cloud
if a dashboard is worth paying for. Migrate to GitHub or GitLab only
if the team already wants to; the report's job is visibility, not
platform evangelism.

## If there is no staging environment

Stand up the branch-staging pattern (see `staging-workflow.md`) before
any redesign, payment change, or CSP enforcement project. Every one of
those has a failure mode that staging makes free to catch.

## If there is no edge at all

Minimum viable move: put Cloudflare's free tier in front (DNS change
plus origin lockdown), or the cloud-native equivalent where the site
already lives. Until then the report runs its traffic leg from server
logs and says, in the edition, that fidelity is reduced and DDoS
posture is "origin exposed".
