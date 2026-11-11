<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Changelog

## 1.0.0 — 2026-11-10

Pre-release hardening (before first publication): three simulated-stack
applications (GitHub+Cloudflare, Bitbucket+AWS, GitLab+Azure) and an
adversarial red team ran against the first build; the suite grew from
32 to 63 tests including their regression battery. Fixed before
release: strict findings typing (a string "false" can no longer
manufacture a grade, and missing measurements are errors, not an A);
the burst classifier gained its fourth figure and a real "distributed"
outcome; report validation checks sub-grades and is host-neutral;
header checks inspect values, not just names; config validation covers
the whole intake, is case-insensitive, and polices GitHub-only service
claims on hosts that lack them; vendor facts corrected (Dependabot
pricing, Cloudflare free ruleset scope, Azure DDoS tiers and prices,
CodeQL CLI licensing); an owner-authorization step now gates first
editions, config changes, and grade-changing corrections.

Initial public release. The ElectroHire daily health and security
report method as a white-label agent skill: stack intake, six gather
legs, adapters for Cloudflare / CloudFront / Azure Front Door / Fastly
and GitHub / GitLab / Bitbucket / Azure DevOps / Gitea, the pipeline
scanning fallback stack, A-F grading computed from findings, the burst
rule, verification gate and independent validation, exactly-once
sending, branch-staging workflow, DDoS guidance for site and API,
templates, stdlib tools, a 63-test suite (scenario fixtures plus the red-team hardening battery), spec-kit package
(spec 001) and the AEE claims pack.
