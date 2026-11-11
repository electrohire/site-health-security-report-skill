<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Site Health & Security Report

An agent skill that produces a graded daily (or weekly) health and security
report for a website, in plain language, for busy owners. It is the method
designed by ElectroHire and generalized to any stack, so the
originating company's projects are not part of the method.

The report answers five questions every day, with evidence:

1. Could people reach the site, and what did traffic actually look like?
2. Can search engines and AI crawlers find and quote it (SEO/AEO)?
3. Is the code safe: vulnerable dependencies, code-scanning findings,
   leaked secrets?
4. Is the perimeter holding: TLS, security headers, email authentication,
   DDoS protection on the site and the API?
5. What are the 3 to 5 highest-impact actions, each with a named owner?

Every edition is graded A to F, overall and in three sub-grades (Traffic &
reliability, SEO/AEO, Security & code health), and every downgrade names its
cause in one line. Numbers are never invented: a source the run cannot reach
is reported as "not available" with the reason.

## Rule zero: never run this skill without a stack intake

Do not assume Cloudflare, GitHub, or any other vendor. Before the first
report, complete the stack intake in `references/stack-intake.md` with the
user and save it as the report config (template: `templates/config.example.json`;
`templates/config.example.yaml` is the human-readable mirror, and the JSON
file is the config of record the tools read). Name the saved file
`config.local.json` (git-ignored), and record credentials by location only
("vault entry X"), never by value. The intake records:

- Edge / CDN / DDoS layer: Cloudflare, AWS CloudFront (+ AWS WAF and
  Shield), Azure Front Door (+ Azure WAF), Fastly, Akamai, Sucuri, or none.
- Code host: GitHub, GitLab, Bitbucket, Azure DevOps, Gitea/Codeberg, or
  other.
- Hosting / origin: cloud provider, region model, staging setup.
- The primary hostname versus side hosts (API, staging, app, workspace).
  This distinction decides outage calls; see the burst rule below.
- Who receives the report, on what schedule, through which sending route,
  and who owns each recommendation class.

If any intake field is unknown, ask. A report built on an assumed stack is
worse than no report, because its gaps look like findings.

## The method (six gather legs)

Run every leg, every edition. A leg that cannot run is listed in the report
as not available, with the reason. Never compose around a missing leg
silently.

1. **Traffic & edge analytics.** Requests, unique visitors, bandwidth,
   cache ratio, status-code mix (2xx/3xx/4xx/5xx), top paths, top
   countries, error anomalies, scanner/probe patterns. Per edge provider,
   see `references/adapters-edge.md`.
2. **SEO / AEO.** An AI-readiness check (for example check.aeojs.org) and
   an SEO check (Seobility, falling back to PageSpeed Insights, falling
   back to the self-run 15-point on-page audit in
   `references/report-writing.md`). Every score carries a scan identifier
   and timestamp from this run.
3. **Code host security.** Open dependency alerts by severity, code
   scanning alerts by severity, secret scanning alerts, and the last
   period's commit and CI/deploy activity. Per code host, including what
   to do when the host has no native scanning, see
   `references/adapters-codehost.md` and
   `references/scanning-fallbacks.md`.
4. **Standing critical items.** Any named, dated item the owner has flagged
   as tracked-until-closed (a CVE in production, a certificate expiring, a
   migration). Dropped only when verified closed.
5. **Website security scans (public, no account needed).** Mozilla
   Observatory grade, SSL Labs TLS grade and certificate expiry, the six
   security headers (an enforcing Content-Security-Policy counts; a
   report-only one does not), HTTP-to-HTTPS redirect, and email
   authentication (SPF, DMARC policy, MX). DDoS posture for the site and
   the API is covered in `references/ddos.md`.
6. **Privacy & AI compliance spot checks (publicly checkable only).**
   Privacy policy names the correct legal entity as controller, covers
   voice/AI-chat data where applicable, names payment processors; AI
   assistants disclose that they are AI at first interaction; cookie
   consent is visible; a data-request route is published. Report each as
   pass, fail, or not-testable, from the page's own text only.

Each leg writes its findings into the edition's findings file; the exact
field names, types, and units are specified in
`references/findings-schema.md`. The findings file is the grading subset;
the report's narrative figures (totals, top paths, scan identifiers) come
from the same legs' dated evidence records, listed in the evidence ledger.

## The burst rule (learned in production)

A spike of 5xx errors is not automatically an outage. Before any outage
call, segment the burst by hostname and by client address:

- If the errors are concentrated on a non-primary host (an API side host,
  a staging host) or come mostly from one client address, it is a scanner
  or probe event against that host, not a site outage, however large the
  zone-wide total looks.
- Grade and write what the segmentation shows. `scripts/site_health.py`
  ships `classify_error_burst()` to make this call mechanically (it needs
  four figures: total errors, errors from the top single address, errors
  on the primary host, and errors on the single busiest host), and the
  test suite carries the regression case. A burst spread across hosts in
  proportion to their traffic classifies as "distributed": an origin or
  region failure pattern, graded on volume, not a scanner event and not
  automatically an outage. After segmentation, grade traffic on the
  residual figures (the day's errors minus the burst's), per
  `references/grading.md`.

## Grading (identical in every white-label deployment)

Full rubric: `references/grading.md`. In short:

- **A**: no critical or high alerts open (a medium/low backlog is
  normal and does not by itself lower the grade), no 5xx problems,
  SEO/AEO 90+.
- **B**: minor issues only (scores 80-89, or minor error noise above the
  clean band, named in one line).
- **C**: any high-severity alert open, scores 70-79, or a noticeable error
  problem.
- **D**: any critical alert open, scores 50-69, or repeated reliability
  problems.
- **F**: a critical alert with a public exploit affecting production,
  scores under 50, or the site is down.

Security sub-grade downgrade causes include: Observatory D or F, SSL Labs
below B, a missing enforcing CSP, no DMARC record (or p=none), code or
secret scanning dark, and any privacy/AI check failing. The overall grade
is the lowest sub-grade. Every downgrade names its cause in one line.
`scripts/site_health.py` computes the grades from a findings file so two
runs on the same evidence cannot disagree.

## Write, verify, validate, then send

Full discipline: `references/verification.md` and
`references/report-writing.md`. The non-negotiables:

1. Compose from saved records only (each leg writes its raw output to a
   dated evidence folder first).
2. Run the pre-send verification gate: re-read every headline figure
   against the record it came from. A figure that cannot be traced is
   corrected or dropped before sending, never after.
3. Run an independent validation pass (an agent or person who did not
   compose the edition re-derives the grades and checks the rendered
   email against the text part).
4. Send exactly once, with an idempotency key per edition, and verify the
   send from the send record (the provider's accepted id in the send
   log), never from a sent-items folder the route does not use.
5. Corrections are sends too: same gate, same validation, same recipients
   copied from the config, never re-typed.

Authorization: the owner approves the first edition and any change to
recipients, sending route, or schedule before it takes effect; the
signed-off config is the standing authorization for scheduled editions
under it. A correction that changes a grade needs the owner's approval
before sending. The tools themselves are run as:

    python3 scripts/site_health.py validate-config config.local.json
    python3 scripts/site_health.py grade findings.json
    python3 scripts/site_health.py burst burst.json
    python3 scripts/site_health.py check-run config.local.json findings.json report.md
    python3 scripts/site_health.py headers https://example.com

An edition (or correction, with `--kind correction`) is validated when
`check-run` passes: it validates the config, the findings, and the
report together, including that the findings do not contradict the
configured stack (scanning recorded as 'none' cannot produce findings
claiming scanning is on; no edge configured cannot produce a protected
edge posture) and that the report's sender and recipients are the
config's, copied, not re-typed. `validate-report` alone checks only
report structure and grade agreement; it is a composition aid, not an
edition validation. No validator verifies narrative figures; that is
the pre-send gate's job, against the evidence records.

Templates: `templates/report-template.md` (white-label: brand name,
colors, recipients, and owner names all come from the config),
`templates/report-email.html`, `templates/correction-template.md`, and
`templates/evidence-ledger.example.md` (the AEE evidence ledger: every
claim in the report traces to a record, with its falsifier).

## Staging websites the same way

This skill pairs with a branch-staging approach proven in production
use: a `staging` branch deploys to a staging
subdomain, production promotes by a reviewed merge, guard files
(robots.txt, response headers) differ deliberately between staging and
production and are verified in the staged tree before promotion, and every
visual change is screenshot-verified on staging and again after promotion.
The full workflow, including the failure modes it prevents, is
`references/staging.md` (extended walkthrough in the repository's
`docs/staging-workflow.md`).

Adapters compose across clouds: the edge provider's section governs
analytics, DDoS, and edge cost; the code host's section governs
scanning; the hosting section governs origin checks, whatever cloud
each part lives in. Where an edge fronts an origin in another cloud,
origin protection uses the edge's published address ranges or an
authenticated pull, and the edition names which.

## Choosing or fixing the stack

The skill works with what the customer has. Where a layer is missing, it
says so as a graded finding with the cost and trade-off of the options,
never as a silent gap:

- No edge/DDoS layer: recommend Cloudflare (free tier is a real option) or
  the cloud-native equivalent that matches their hosting; see
  `references/ddos.md` (the repository's `docs/stack-selection.md`
  carries worked stack comparisons with prices).
- Bitbucket (or any host) without native code scanning: run the fallback
  stack in the pipeline (Semgrep for SAST, gitleaks for
  secrets, Trivy or OSV-Scanner for dependencies and containers), or a
  commercial scanner (Snyk, Mend, SonarQube); the report reads the
  pipeline's saved scan outputs exactly as it would read native alerts.
  Details and limits: `references/scanning-fallbacks.md`.
- No staging environment: recommend the branch-staging pattern above
  before any redesign work.

## What this skill must never do

- Never invent a number, a scan result, or a send confirmation.
- Never call an outage without the burst rule's segmentation.
- Never present a fallback checker's score as the primary checker's.
- Never send from an account or route the config does not name.
- Never write to production repositories, settings, or infrastructure
  unless the user's directive names the repo and the exact action.
