<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Why each part exists: protection, cost, trade-offs

The report is not a dashboard export. Each leg exists because a class of
real failure is invisible without it, and each has a price. This page is
the honest sales sheet, including where the answer is "you may not need
this yet".

## Traffic analytics, segmented

- **Protects against**: silent outages, bad deploys, broken links at
  scale, scanner storms eating origin capacity, and the opposite error,
  crying outage over a probe burst on a side host.
- **Why segmentation matters**: zone-wide totals lie by aggregation. The
  real production case behind the burst rule: thousands of SSL errors in
  two burst hours graded a live site "down" until per-host, per-address
  segmentation showed a single scanner working an API side host.
- **Cost**: a read-only analytics token and a few minutes of API calls a
  day. **Trade-off**: free analytics tiers keep roughly a month of
  detail; older comparisons need the report's own saved records, which
  is one more reason every edition archives its evidence.

## SEO / AEO checks

- **Protects against**: de-indexing accidents (a staging robots.txt
  promoted to production is the classic), metadata regressions, and
  invisibility to AI answer engines, which increasingly mediate
  discovery.
- **Cost**: free checkers have daily caps (Seobility's free tier is
  about three checks a day), hence the fallback chain. **Trade-off**:
  scores are proxies, not rankings; the report treats them as smoke
  alarms, not grades of the business.

## Dependency, SAST, and secret scanning

- **Protects against**: the most common real-world breach paths:
  a known-vulnerable library, an injection flaw a dataflow query would
  have caught, and a credential committed once and cloned forever.
- **Cost**: Dependabot dependency alerts are free everywhere; code and secret scanning are free on public repos and licensed on
  private ones (GitHub Advanced Security is per-committer). The free
  fallback stack (Semgrep, gitleaks, OSV-Scanner, Trivy) costs pipeline
  minutes and triage time instead. **Trade-off**: free SAST rules are
  shallower than CodeQL's dataflow analysis; for payment, health, or
  auth-heavy products the report recommends the upgrade explicitly.
- **The rule that matters**: a scanner whose results nobody reads is
  graded dark. Coverage means read, daily, with counts that move.

## Security headers, TLS, email authentication

- **Protects against**: clickjacking, MIME confusion, downgrade and
  referrer leakage (headers); expired-certificate outages, which are
  embarrassingly common (the report watches the 14-day horizon); and
  domain spoofing (DMARC at p=reject is the difference between "please
  don't" and "mail servers must refuse").
- **Cost**: headers are configuration, an afternoon at most; the
  enforcing CSP is the one real project, because it must be staged
  report-only first and its violations triaged. **Trade-off**: an
  enforcing CSP can break third-party widgets; that is what the
  report-only runway is for, and why the report never counts
  report-only as done.

## DDoS posture, site and API

- **Protects against**: L3/4 floods (only edge capacity helps), L7
  floods against login, search, and API endpoints, and denial-of-wallet
  on pay-per-request stacks.
- **Cost**: Cloudflare's free tier is genuinely sufficient for many
  sites; AWS and Azure equivalents price very differently (WAF per
  rule and request; Azure DDoS flat and high). **Trade-off**: every
  edge adds a TLS termination point and a debugging layer, and rate
  limits must be tuned so a customer's office NAT is not one "user".
  Full treatment: `skills/site-health-security-report/references/ddos.md`.

## Privacy and AI spot checks

- **Protects against**: the quiet compliance failures that surface in
  diligence or a regulator's first letter: a privacy policy naming the
  wrong company (this happened, on a real site, in this method's own
  history), an AI assistant that never says it is AI, no published
  route for data requests.
- **Cost**: minutes; the checks are public-page reads. **Limit**,
  stated in every edition: spot checks are not a compliance audit.

## The graded, owned, daily format itself

- **Protects against**: the actual failure mode of most monitoring,
  alerts with no owner rotting in a channel. A grade forces a verdict;
  a named cause forces a fix list; a named owner forces a person;
  the follow-up line forces yesterday's promises to be revisited.
- **Cost**: one email a day and the discipline to read it.
