<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Stack intake (required before the first report)

Ask the user, record the answers in the report config, and confirm the
config back to them before the first edition. Every field exists because a
report written without it has produced a real error somewhere.

| Field | Why it matters |
|---|---|
| Primary hostname (e.g. `example.com`) | The outage definition applies to this host. |
| Side hostnames with roles (API, staging, app/workspace, admin) | Error bursts on side hosts are graded as events on that host, never as primary-site outages. |
| Edge / CDN / DDoS provider | Decides which analytics API and which DDoS controls the report checks (Cloudflare, CloudFront + WAF/Shield, Azure Front Door + WAF, Fastly, Akamai, none). |
| Edge analytics credential | Must be read-only and scoped to the one site/zone. Never a global key. Record **where it lives** (vault entry name), never its value; the saved config must be safe to commit in redacted form and is named `config.local.json` (git-ignored). |
| Code-host access | Read-only in the same way: a scoped read token where the host supports one. Where the agent instead uses the user's existing signed-in CLI session, record that fact here; that session is never used to write. |
| Sender identity | The From display name and address on the customer's own sending domain (the report template's sender comes from this field, not from prose). |
| Code host instance | Recorded for any host where it changes what applies (GitLab, Azure DevOps, Gitea, other): `saas` or `self-managed`. The validator warns when it is missing on those hosts. |
| Edge tier / plan | Optional but recommended: the edge plan (free, Pro, Premium, Shield Advanced, and so on). The adapters' DDoS and WAF claims are tier-dependent, and the findings' `edge_posture` rests on it. |
| Code host add-ons | Optional: licensed add-ons that change the scanning vocabulary, today `ghazdo` for Azure DevOps. |
| Code host and organization | Decides the scanning source (GitHub, GitLab, Bitbucket, Azure DevOps, Gitea). |
| Repository list (the product set) | The report covers a named set, not "everything in the org". |
| Scanning stack actually in place | Native (Dependabot/CodeQL, GitLab SAST, ...) or pipeline fallbacks (Semgrep, gitleaks, Trivy, OSV-Scanner, Snyk). Record which, per scan type: dependencies, SAST, secrets. |
| Hosting / origin | Decides TLS and origin-protection checks, and where staging lives. |
| Staging setup | Staging URL, branch, promotion path, recorded as an object; or the bare string "none". "None" is a finding, not a blocker. |
| Report recipients and owners | To/Cc, and the named owner for each recommendation class (edge, code, content, business decision). |
| Sending route | The customer's own sending account on their verified domain (e.g. Resend, SES, SendGrid, Microsoft 365). The skill never sends from the agent's accounts. |
| Schedule and timezone | Daily or weekly, the delivery time, and the timezone the "previous day" is computed in. Edge analytics days are usually UTC; the report says so when it matters. |
| Tracked standing items | Named, dated items graded until verified closed (a production CVE, a cert renewal, a migration). |
| Application platform (`app_platform`, optional) | A platform whose components update separately from the code (WordPress, a CMS): which platform, and the advisory source leg 3 reads. |
| Site backups (`site_backups`, optional) | How the site itself is backed up and when a backup was last verified; feeds findings' `site_backups_verified`. |
| Brand (white-label) | Display name, logo URL, accent color, sender display name for the HTML template. |

## Intake questions (ask verbatim, one short list)

1. What is the site's main web address, and what other hosts belong to it
   (API, staging, app, admin)?
2. What sits in front of it, if anything: Cloudflare, AWS CloudFront,
   Azure, Fastly, something else, or nothing?
3. Where does the code live: GitHub, GitLab, Bitbucket, Azure DevOps,
   somewhere else? Which repositories are the product?
4. What scans the code today for vulnerable dependencies, code flaws, and
   leaked secrets, if anything does?
5. Where is it hosted, and is there a staging site? How do changes reach
   production?
6. Who should receive the report, how often, and who owns fixing what it
   finds?
7. Is there anything already known-broken or being watched that the
   report should track until it is verified fixed?
8. Where does the credential for reading the edge analytics live, and
   where does the credential for reading the code host live? (Locations
   only, never the values: a vault entry name, an environment variable
   name, a file path.)
9. What name and address should the report send from, and through which
   sending service on your own domain?
10. What timezone should the report's covering period be computed in,
    and at what time should it arrive? (At weekly cadence, also record
    the covering convention, e.g. Monday to Sunday.)
11. What display name and accent color should the report carry?
12. Does the site run on an application platform whose own components
    update separately from the code (WordPress core and plugins, a
    CMS, a shop platform)? If so, which, and who announces its
    vulnerabilities? And how is the site itself backed up, and when
    was a backup last verified?

Record "unknown" honestly where the user does not know. An answer
that is publicly checkable (DNS, response headers, the platform's
public version files) may be verified from public evidence instead
of asking, and the record says which. Where the customer has no
sending service yet, setting one up on their own domain is part of
adoption (allow about an hour, guided). A signed-in browser or
dashboard session is an acceptable credential location for the edge
as it is for the code host, recorded the same way. The config is
confirmed back to the owner in plain language, not as raw JSON; the
first edition
then treats closing that unknown as a recommendation. Note that the
config validator requires the table's fields to be present (the optional
extras are `code_host_instance`, `edge_tier`, `code_host_addons`,
`app_platform`, `site_backups`, and
`code_host_ci` (the CI system the pipeline scanners run under, where
the host offers a choice — Gitea Actions vs Woodpecker on Gitea),
recorded when they apply): an honest "none" or a named placeholder
passes; a silently absent field does not. (The organization half of
"code host and organization" lives inside the repository paths
themselves, e.g. `trailmark/storefront`.) At sign-off, the owner
confirms each named scanner was seen enabled through its adapter read
path (references/adapters-codehost.md): the validator checks that the
names are real tools for the host, and sign-off is where existence is
verified.
The owner approves the completed config (and any later change to
recipients, route, or schedule) before editions run under it: the
signed-off config is the standing send authorization.

## Amending a signed-off config (migrations and stack changes)

A change to the stack itself (code host, scanning tools, edge
provider, hosting, staging) is an amendment, and it follows the same
discipline as sign-off:

1. Owner approval, recorded, before the amended config takes effect
   (the approval list above names the send-facing fields; a stack
   change re-points the sources of record and needs the owner's go
   for the same reason).
2. Partial re-intake: re-answer the intake questions covering the
   changed fields, and re-apply the sign-off check to them (each
   newly named scanner seen enabled through its adapter read path).
3. Keep the superseded config as a versioned file next to the live
   one (`config.local.v1.json`, `config.local.v2.json`, ...). A
   correction to an edition validates against the config version
   that governed that edition, so the history is load-bearing, not
   bookkeeping.
4. The amended config governs from the first edition whose covering
   day ends after the amendment takes effect; an edition whose
   covering day straddles the change is composed under the amended
   config and narrates the switch in WHAT CHANGED.
5. `standing_items` is a list of strings. A standing item is verified
   closed when an edition's own records show its condition resolved;
   that edition states the evidence, and the entry is annotated
   `closed <date>` in the config, never deleted. The date is the
   closing edition's covering date. Adding an item mid-run is not an
   amendment and needs no approval; record it in the run log.
