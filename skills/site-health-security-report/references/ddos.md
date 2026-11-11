<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# DDoS protection: what the report checks, and why

## The two attacks are different problems

- **Network floods (L3/4)**: raw packet volume aimed at saturating the
  link. Only an edge with real capacity absorbs these; no origin-side
  setting substitutes. Cloudflare, AWS Shield, Azure DDoS Protection,
  Fastly, and Akamai all sell, fundamentally, this capacity.
- **Application floods (L7)**: HTTP requests that look normal
  individually: login hammering, search or API scraping, cache-busting
  query strings, scanner bursts (archive probes, `.env` hunts). These
  are stopped by rules: rate limits per address, managed WAF rules,
  bot management, and caching that keeps requests off the origin.

A site "behind Cloudflare" with no rate limiting and an origin anyone
can reach directly has L3/4 cover and almost no L7 cover. The report
grades both halves.

## The checklist (checked every edition, changes reported)

1. Edge proxy actually on for the primary host **and the API host**.
   The API is the softer target: it is dynamic, uncacheable, and
   usually rate-limit free. Name it separately in the report.
2. Managed DDoS and WAF rulesets enabled (not just available).
3. Rate-limit rules on: login and password reset, sign-up, search, any
   endpoint that sends email or SMS (abuse = money), and the API's
   expensive endpoints. Starting points (always deploy in count/log
   mode first and tune against a week of real traffic): auth endpoints
   at ~100 requests per 5 minutes per address for the observation week,
   then enforce at 3–5× the observed legitimate p99; general API at
   ~2,000 requests per 5 minutes per address. Thresholds are starting
   points, not guarantees; the report names the current numbers it
   verified, per endpoint.
4. Origin protection: the origin accepts traffic only from the edge
   (Cloudflare Tunnel or authenticated origin pull, AWS security groups
   restricted to CloudFront prefixes, Azure equivalents), and the
   origin's real address is not in public DNS history or certificates
   where avoidable. Without this, every edge control can be walked
   around.
5. Cache posture: static assets cached at the edge with long TTLs; a
   cache-bypass flood should still hit cache for everything cacheable.
6. Scanner-burst handling: known probe patterns (backup archives,
   `.env`, `wp-admin` on non-WordPress sites) blocked or challenged,
   and alerts on per-address request rates so a burst is an event with
   an owner, not a surprise in tomorrow's report.
7. Cost circuit-breakers where the stack bills per request (AWS WAF,
   Lambda, egress): budgets and alarms set, because an L7 flood on a
   pay-per-request stack is a billing attack ("denial of wallet").

## What it protects, in owner language

Availability during attacks and scanner storms; the origin's address
staying boring; the cloud bill staying predictable; and real customers
not competing with bots for the login endpoint.

## Costs and trade-offs

- Cloudflare free tier covers a surprising amount (unmetered L3/4,
  the DDoS managed rulesets, and a small free managed WAF ruleset);
  paid tiers buy the full managed WAF, finer rate limiting, better bot
  management, and support. Trade-off: TLS terminates at the edge, and
  debugging gains a layer.
- AWS: Shield Standard is free and automatic; WAF is pay-per-rule and
  per-request; Shield Advanced is a four-figure monthly commitment that
  only pencils out for proven targets.
- Azure: Front Door carries built-in platform-level protection.
  DDoS Network Protection is $2,944/month per protection plan; for
  one or a few origin addresses, DDoS IP Protection at $199/month per
  public IP is the tier a small site actually buys; above that shape,
  small sites often do better with a different edge in front.
- Rate limits always trade against legitimate bursts (a customer behind
  corporate NAT is one address). Start in log/count mode, then enforce.
