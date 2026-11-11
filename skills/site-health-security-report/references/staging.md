<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Staging websites: the branch-staging app approach

A production-proven approach, stated so any customer can adopt it.

**Authorization gate:** promotion merges and guard-file changes are
production writes. Run them only under a directive naming the repo and
the exact action, or a standing authorization recorded in the customer's
config. This reference describes the mechanics; it does not grant the
authority. By design, this skill ships no tool surface for promotion:
the report tooling validates reports, and promotion stays an owner act
under this gate and the procedure below. That is deliberate, not an
omission: a merge is not a report artifact, and no validator in this
skill can see one.

## The shape

- Two long-lived branches: `staging` and `main` (production).
- The hosting platform (Cloudflare Pages, Vercel, Netlify, Azure Static
  Web Apps, AWS Amplify, or an S3+CloudFront pair per environment)
  deploys `staging` to a staging subdomain (for example
  `staging.example.com`) and `main` to the production domain.
- Feature work merges to `staging` first. What stakeholders approve on
  the staging URL is exactly what promotes.
- Promotion is a merge from `staging` to `main`. Where guard files
  differ between environments (below), promotion is a **local** merge
  whose staged tree is inspected before commit, never a blind API
  merge.

## Guard files: the part everyone gets wrong

Staging and production deliberately differ in a small set of files:

- `robots.txt`: staging disallows all crawling; production allows it.
- Response headers (`_headers`, platform config): staging carries
  `X-Robots-Tag: noindex`; production must not.
- Analytics and third-party keys: staging uses test keys or none.

Failure modes this prevents, all observed in real work:

1. A promotion that silently carries staging's disallow-all robots.txt
   to production, de-indexing the live site.
2. A main-to-staging sync merge that strips staging's guards, leaving
   staging crawlable and indexable.
3. A visual fix verified against a stale cached stylesheet; bump the
   stylesheet to a versioned filename on visual changes so no cache can
   serve the old one.

Rules: after any sync merge in either direction, re-assert the target
branch's guard files and diff them against the other branch's: the diff
must be exactly the known guard lines, nothing else.

## The approval gate

- Web work starts from a spec, and UI work from a wireframe the owner
  approves by name before build (spec-kit flow: specify, plan, tasks,
  implement; see `specs/` in this repository for the pattern).
- Verification is visual: render the change on staging with a browser
  (Playwright or equivalent), screenshot desktop and mobile widths,
  compare against the approved wireframe, and only then call it
  verified. Source-level checks (curl, grep) are necessary and nowhere
  near sufficient; broken layouts routinely pass them.
- After promotion, repeat the screenshot check on production, plus a
  served-identity check: fetch a build stamp or content signature that
  only the new build has. "The port answers" is not verification.

## Dynamic origins (an app on EC2, a VPS, or similar)

The branch-app platforms above fit static and serverless sites. A
dynamic app on a virtual machine stages differently, with the same
branch discipline:

- Same artifact, second environment: build once; deploy the identical
  build to a small staging instance (a small instance type is fine)
  behind the staging subdomain, as its own target: a separate
  distribution or load-balancer listener rule pointing at the staging
  instance, never a path on the production host.
- Data: staging runs on a restored snapshot or seeded data, refreshed
  on a schedule, with real customer data masked or excluded; it never
  points at the production database.
- Guards carry over: staging is disallowed in robots terms and carries
  noindex headers (set them in the staging environment's response
  headers policy or app config), uses test payment and email keys, and
  its outbound email is trapped, not delivered.
- Promotion is the same reviewed merge plus a deploy of the already
  approved build; the guard set for each environment lives with that
  environment's configuration, and the staged-tree check becomes a
  staged-environment check (headers and robots fetched from each live
  environment before the promotion is called done).

## Environments beyond staging

Preview deployments per pull request (all the platforms above offer
them) slot under staging for review; the staging branch remains the one
integration point stakeholders approve. Secrets differ per environment
and live in the platform's environment settings, never in the repo.
