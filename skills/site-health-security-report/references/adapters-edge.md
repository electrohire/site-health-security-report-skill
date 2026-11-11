<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Edge adapters: traffic analytics and DDoS posture by provider

The report needs the same facts from every edge: requests, uniques,
bandwidth, cache ratio, status mix, top paths, top countries, and error
detail **segmented by hostname and, for bursts, by client address**. How
to get them, and what DDoS controls to check, per provider.

## Cloudflare

- Analytics: GraphQL Analytics API (`httpRequests1dGroups` for daily
  totals, adaptive groups for top paths/countries, firewall events for
  per-address detail). Credential: an API token with Zone Analytics Read
  + Zone Read on the single zone. Never a global API key.
- Segmentation: filter by `clientRequestHTTPHost` for host, and use
  firewall/security events for per-address burst analysis.
- DDoS controls to verify: "Under Attack" readiness, DDoS managed
  ruleset enabled, WAF managed rules, rate-limiting rules on login, API,
  and expensive endpoints; bot fight mode or Super Bot Fight Mode;
  cache rules that keep HTML cacheable where safe.
- Cost note: the free plan includes unmetered L3/4 DDoS mitigation, the
  DDoS managed rulesets, and a small *Free Managed Ruleset* subset of WAF
  rules. The full Cloudflare Managed Ruleset, most WAF custom rules, and
  advanced rate limiting are paid-tier features; do not report a free-tier
  site as having full managed WAF coverage. Trade-off: proxying means TLS
  terminates at Cloudflare; the origin must still be locked down (see
  origin protection in `ddos.md`) or the proxy is theatre.

## AWS CloudFront + AWS WAF + Shield

- Analytics: CloudFront standard logs or real-time logs to S3/Athena, or
  CloudWatch metrics (Requests, BytesDownloaded, 4xxErrorRate,
  5xxErrorRate, TotalErrorRate). Prefer the logs: CloudWatch metrics
  cannot segment by host or client address, and the burst rule needs
  exactly those cuts. The log fields that matter: `cs(Host)`, `c-ip`,
  `sc-status`, `x-edge-result-type`, `cs-uri-stem`. Example Athena cut:
  `SELECT "cs(host)", "c-ip", count(*) FROM cloudfront_logs WHERE
  sc_status >= 500 GROUP BY 1, 2 ORDER BY 3 DESC`. The credential for
  this leg needs read access to the log bucket only.
- DDoS controls: AWS Shield Standard is automatic for CloudFront
  (L3/4). Shield Advanced adds cost protection (credits for the
  attack-driven part of the bill) and 24/7 DRT access, at roughly
  $3,000/month per organization with a 1-year commitment, worth it only
  for high-value targets. AWS
  WAF provides managed rule groups (core, known bad inputs, IP
  reputation) and rate-based rules (per-IP request caps) for L7.
- Watch out: CloudFront error rates mix origin and edge errors;
  `x-edge-result-type` in logs separates them. A 5xx burst at the API's
  alternate domain name is not a main-site outage (burst rule).
- Cost note: pay per request plus per WAF rule and ACL; cheap at small
  scale, and the bill scales with attack traffic unless Shield Advanced
  cost protection applies.

## Azure Front Door + Azure WAF

- Analytics: Azure Monitor metrics and Front Door access logs in Log
  Analytics; KQL does per-host/per-IP segmentation.
- DDoS controls: Azure DDoS Protection (network tier) for the origin's
  public IPs; WAF policy in Prevention mode with the managed default
  rule set and rate-limit rules; bot manager ruleset on Premium.
- Note: Front Door itself carries built-in platform-level DDoS
  protection; the paid tiers below protect the origin's public IPs.
- Cost note: DDoS Network Protection is $2,944/month per protection
  plan (100 public IPs included), which is often the deciding factor
  for small sites. The tier a small site actually buys is usually DDoS
  IP Protection at $199/month per public IP (cheaper below roughly 15
  protected addresses). Above that shape, the honest recommendation
  may be a cheaper edge in front instead. (Prices are 2026 list-price
  shapes; verify at purchase.)

## Fastly

- Analytics: Fastly API stats (historical and real-time) and log
  streaming to your own store for per-host/per-IP cuts.
- DDoS controls: Fastly's platform absorbs L3/4; the Next-Gen WAF
  (Signal Sciences) is a separate product for L7 rules and rate
  limiting. Verify it is actually attached; a bare CDN config is not a
  WAF.

## Akamai, Sucuri, and others

- Same contract: find the analytics export that segments by host and
  client address, confirm the managed DDoS ruleset is on, confirm
  rate limiting exists on login/API paths, and record the gaps as
  findings when any of those is "the vendor says it is handled" without
  a console-visible control.

## No edge layer

Report it plainly as a finding with the recommendation (the
repository's `docs/stack-selection.md` carries the worked comparison):
the origin takes raw internet traffic, there
is no L7 filtering and no per-address analytics, so the report's traffic
leg degrades to server-log analysis (GoAccess, AWStats, or the host's
log analytics) and the burst rule runs on log data. That works, at lower
fidelity, and the report says so.
