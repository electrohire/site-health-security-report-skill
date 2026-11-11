<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Scanning fallbacks: full coverage on any host

When the code host has no native scanning (Bitbucket, Azure DevOps
without GHAzDO, Gitea), or licensing blocks it (GitHub private repos
without Advanced Security), run these in CI on every push to the main
branches and on a schedule. All are free and open source except where
noted. Save each tool's JSON output as a dated artifact; the daily
report's leg 3 reads the latest artifacts.

| Scan type | First choice | Also good | Notes |
|---|---|---|---|
| Secrets | gitleaks | trufflehog (verified-secret mode) | Run on the full history at setup, then per-commit in CI. Push-time prevention: a pre-receive hook or the host's push rules where available. |
| SAST / code flaws | Semgrep (OSS rules) | SonarQube Community; CodeQL CLI **only where licensed**: using it on closed-source code outside GitHub generally requires GitHub Advanced Security, so it is not the free fallback for a Bitbucket/Azure DevOps customer | Semgrep's free rules catch the common classes; its paid rulesets deepen coverage. |
| Dependencies | OSV-Scanner | Trivy, `npm audit`, `pip-audit`, `cargo audit` | OSV-Scanner reads lockfiles across ecosystems and queries the OSV database; Trivy adds container images and IaC. |
| Containers / IaC | Trivy | Grype, Checkov (IaC) | Only where images or IaC exist. |
| Dependency update PRs | Renovate | Dependabot (GitHub only) | Detection without updates rots; pair them. |

## Pipeline shape (host-neutral)

```yaml
# Pseudocode; translate to the host's CI syntax.
security-scan:
  when: push to main/develop, nightly schedule, manual
  steps:
    - gitleaks detect --redact --report-format json --report-path out/gitleaks.json
    - semgrep scan --config auto --json --output out/semgrep.json
    - osv-scanner -r . --format json --output-file out/osv.json   # or: trivy fs . --format json
  artifacts: out/   # retained at least 35 days so a daily report always has a fresh record (and a weekly one several)
  policy: the pipeline does NOT fail the build by default in week 1.
          It reports. Failing builds on day one is how scanners get
          switched off; tighten after the backlog is triaged.
```

Bitbucket Pipelines, GitLab CI, Azure Pipelines, and GitHub Actions all
express this shape directly; Atlassian "pipes" exist for Semgrep, Snyk,
and Sonar, and plain script steps work everywhere.

## Commercial options (when the customer prefers a dashboard)

- **Snyk**: dependency, SAST, container, and IaC in one dashboard, with
  Bitbucket/GitLab/Azure integrations. Per-developer pricing.
- **SonarQube Cloud**: strong SAST and quality gates, Bitbucket-native
  decoration of pull requests. Priced by lines of code.
- **Mend, DeepSource, GitGuardian** (secrets, best in class): each can
  be the right single-purpose answer.

The report grades coverage, not brand: any of these, read daily, counts
as scanning on. The trade-off to state plainly is cost per seat versus
the engineering time to run the free stack, and the fact that a
dashboard nobody opens is graded dark.

## Limits, stated honestly

- Free SAST rules miss classes that CodeQL's dataflow queries catch;
  where the product handles payments, health data, or auth at scale,
  recommend CodeQL (native or GHAzDO) or a commercial engine as the
  upgrade path.
- Secret scanning finds committed secrets; it does not undo them. A
  found secret is an incident: rotate first, then clean history.
- Dependency scanners know published advisories. They say nothing about
  malicious packages with no advisory yet; lockfiles, pinned versions,
  and update review are the compensating controls.
