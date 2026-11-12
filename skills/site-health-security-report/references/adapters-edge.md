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
  + Zone Read on the single zone. Never a global API key. Where the
  owner reads the dashboard manually, their signed-in session is an
  acceptable credential location instead; record which one the
  deployment uses in the config.
- Segmentation: filter by `clientRequestHTTPHost` for host, and use
  firewall/security events for per-address burst analysis. For a
  partial window (a mid-period switch, a non-UTC covering period),
  sum the hourly groups instead of the daily ones and say so in
  the evidence record.
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
  Analytics; KQL does per-host/per-IP segmentation. Example cut over
  the `AzureDiagnostics` Front Door access log:
  `AzureDiagnostics | where Category == "FrontDoorAccessLog" | where
  toint(httpStatusCode_d) >= 500 | summarize count() by host_s,
  clientIp_s | order by count_ desc`.
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

- Analytics: the Fastly Stats API (historical and real-time) gives
  totals and status mixes per service (`GET /stats/aggregate` with
  `by=hour` for a covering period); the per-host/per-address cuts
  the burst rule needs come from log streaming to your own store
  (S3, BigQuery, or a log platform), with a log format that includes
  the host, client IP, status, and request path, for example:
  `{"host":"%{req.http.Host}V","ip":"%a","status":%s,"path":"%U","geo":"%{client.geo.country_code}V"}`.
  After configuring the stream, read one delivered record and
  confirm every field the burst rule needs is actually in it: a
  stream missing the host field cannot segment, and the edition
  that discovers that is a classification-pending edition.
  Credential: a Fastly API token with read-only (global read)
  scope on the one service, recorded by location in the config.
  The Stats API carries no unique visitors and no country cut:
  uniques come from the log store (distinct client addresses), and
  countries only if the log format carries a geo field (the
  `client.geo.country_code` VCL variable, as in the example above);
  otherwise both print as not available, never estimated.
  With no log stream configured at all, the disposition is: a
  period with no error spike grades on the Stats API totals with
  the lower fidelity named next to the grade; a period with an
  error spike is a classification-pending edition, because the
  spike cannot be segmented.
- Record the plan in the config's `edge_tier` (free text: what the
  service actually carries, for example "CDN only" or "Next-Gen WAF
  licensed and attached"): the Next-Gen WAF is a separately
  licensed product, so the tier decides the `edge_posture` finding.
- DDoS controls: Fastly's platform absorbs L3/4; the Next-Gen WAF
  (Signal Sciences) is a separate product for L7 rules and rate
  limiting. Verify it is actually attached; a bare CDN config is not a
  WAF, and grades as `edge_posture: cdn-only` until it is.

## Netlify, Vercel, and Bunny

These three are first-class `edge_provider` values. Each is usually
also the hosting platform, which the config records in `hosting`;
the edge contract is the same as every provider's: an analytics
source that segments by host and client address, a visible WAF or
equivalent control for a `protected` posture, and gaps recorded as
findings rather than assumed away.

- Netlify starting points: site analytics and server-side log
  records for totals and status mixes; per-address and per-host
  cuts for the burst rule come from log drains to your own store
  where the plan provides them — confirm the drain carries host,
  client address, and status before the first edition, and treat a
  missing cut like any other unsegmentable edge (lower fidelity,
  named). Response headers are set in the platform's header
  configuration (`_headers` / `netlify.toml`); the platform's
  firewall/traffic controls are the WAF evidence, verified in the
  console, not assumed from the plan name.
- Vercel starting points: the project's analytics and runtime logs
  for totals; per-address cuts come from log drains to your own
  store where configured, with the same field confirmation as
  Netlify. Headers are set in the project's configuration
  (`vercel.json` / framework config); the WAF and attack-challenge
  controls are verified in the project settings.
- Bunny starting points: the CDN's traffic statistics and log
  delivery (to your own store) for the burst rule's cuts, with the
  log fields confirmed on one delivered record; the Shield/WAF
  tier attached to the pull zone is the posture evidence, recorded
  in `edge_tier`.

## Akamai, Sucuri, and others

- Same contract: find the analytics export that segments by host and
  client address, confirm the managed DDoS ruleset is on, confirm
  rate limiting exists on login/API paths, and record the gaps as
  findings when any of those is "the vendor says it is handled" without
  a console-visible control.
- Akamai starting points: reporting in Control Center for totals;
  DataStream 2 log delivery (host, client IP, status) to your own
  store for the burst rule's cuts; the WAF product is App & API
  Protector (with Bot Manager where licensed); L3/4 scale is the
  platform's core offer, with Prolexic for dedicated network defense.
- Sucuri starting points: the Website Firewall dashboard's traffic and
  attack reports are the analytics source; verify its export actually
  segments by host and client address before the first edition, and
  record the answer in the config notes. The posture evidence is the
  firewall's protection status and ruleset state in that dashboard;
  where the export cannot segment, the edge grades at lower fidelity
  with the caveat named, exactly as for any unsegmentable edge.
- An edge recorded as `other` (a regional or homegrown CDN) follows
  this same contract, and the config's `notes` field (required for
  `other`) names what the export is. If the edge cannot segment by
  host and client address at all, the burst rule cannot run: the
  edition says the traffic leg ran at lower fidelity, grades traffic
  on the totals with that caveat named next to the grade, and never
  makes an outage call from unsegmented data.

## No edge layer

Report it plainly as a finding with the recommendation (the
repository's `docs/stack-selection.md` carries the worked comparison):
the origin takes raw internet traffic, there
is no L7 filtering and no per-address analytics, so the report's traffic
leg degrades to server-log analysis (GoAccess, AWStats, or the host's
log analytics) and the burst rule runs on log data. That works, at lower
fidelity, and the report says so.
