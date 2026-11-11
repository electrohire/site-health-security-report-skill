<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# The branch-staging workflow (user guide)

The full rules live in the skill's
[`references/staging.md`](../skills/site-health-security-report/references/staging.md).
This is the short version for setting it up.

1. **Two branches.** `staging` and `main`. The host deploys `staging`
   to `staging.yourdomain.com` and `main` to production.
2. **Guard files per branch.** Staging: `robots.txt` disallows all,
   headers carry `X-Robots-Tag: noindex`. Production: the opposite.
   These files differ on purpose; every merge in either direction
   re-asserts the target branch's versions, and the diff between
   branches for these files must be exactly the guard lines.
3. **Work flows one way.** Features merge to `staging`; stakeholders
   approve the staging URL; promotion merges `staging` into `main`.
   Promotions that touch guard files are local merges with the staged
   tree inspected before commit, never blind API merges.
4. **Verify visually, twice.** Screenshot staging at desktop and mobile
   widths against the approved wireframe before promotion, and
   production after it, checking a build stamp that only the new build
   carries. A 200 response is not verification.
5. **Version visual assets.** Rename the stylesheet on visual changes
   (`styles.v14.css`) so no cache, yours or a visitor's, can serve the
   old look and fake a failed fix.

Platform notes: Cloudflare Pages and Netlify map branches to
subdomains in project settings; Vercel calls them preview/production
environments (pin `staging` as a custom preview branch); Azure Static
Web Apps stage per pull request, so treat the PR environment as review
and keep a long-lived staging resource fed by the `staging` branch;
AWS Amplify supports branch deployments directly, and S3+CloudFront
needs one bucket and distribution per environment.
