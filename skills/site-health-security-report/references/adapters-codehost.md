<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Code-host adapters: dependency, code, and secret scanning by host

The report needs three counts per product repository, by severity:
vulnerable dependencies, code-scanning (SAST) findings, and secret
scanning findings, plus what changed since the last edition and the
period's commit/CI/deploy activity. Where each host gets them:

## GitHub

- Dependencies: Dependabot alerts (API: `/repos/{o}/{r}/dependabot/alerts`).
  Dependabot alerts and security updates are free for all repositories,
  public and private. (It is code scanning and secret scanning below
  that need GitHub Advanced Security licensing on private repos.)
- SAST: CodeQL via code scanning alerts API. Free for public repos;
  private repos need GitHub Advanced Security licensing.
- Secrets: secret scanning alerts API; same licensing shape as CodeQL.
  Push protection is the control that stops the secret landing at all.
- Activity: commits and Actions runs via the API, per repo.
- If scanning is dark because of licensing, the finding names the exact
  unlock (plan or GHAS) and its cost; the fallback stack below is the
  interim answer.
- Language coverage: CodeQL does not analyze PHP (and several other
  languages); on a repo whose main language it does not cover,
  `code_scanning_on` means the tool is enabled, not that the code is
  analyzed — the edition narrates the coverage limit and the fallback
  (Semgrep covers PHP) is the honest SAST source.

## Application platforms (WordPress and similar)

Where the product runs on a platform whose components live outside
the repositories (WordPress core, plugins and themes installed from
the platform's directory; a CMS's modules), leg 3 also reads the
platform: installed versions from the platform's own surface (the
admin update screen, or the public version file a plugin ships),
matched against the named advisory source (the vendor's notices,
the host's security mail, a vulnerability database). Open criticals
and highs are recorded in findings as `security.platform` with the
source named, and an exploited platform critical authorizes the
incident note like any other.

## GitLab

- Dependencies: Dependency Scanning (CI template) feeds the
  Vulnerability Report; container scanning likewise. The Vulnerability
  Report UI is an Ultimate-tier feature. Scanner availability and
  behavior vary by tier, GitLab version, and (on self-managed) the
  instance's license and admin settings: verify what your instance
  actually runs, and note SaaS vs self-managed in the config
  (`code_host_instance`). Where the jobs run, their JSON artifacts can
  be read directly, which is what this skill does.
- SAST: GitLab SAST (Semgrep-based analyzers) via CI template.
- Secrets: Secret Detection CI job (gitleaks-based).
- Activity: project events and pipeline APIs.
- Reading the artifacts: save the pipeline's report files
  (`gl-dependency-scanning-report.json`, `gl-sast-report.json`,
  `gl-secret-detection-report.json`) as the leg's evidence records.

## Bitbucket Cloud

The honest position, because the report must never pretend otherwise:
**Bitbucket Cloud has no native Dependabot equivalent, no native SAST,
and no native secret scanning.** What exists:

- "Security" tab integrations are third-party apps (Snyk, SonarQube,
  DeepSource, and others) whose results live in their own dashboards.
- Bitbucket Pipelines can run any scanner as a step, and Atlassian
  publishes pipes for several. **This is the working route**, detailed in
  `scanning-fallbacks.md`: gitleaks (secrets), Semgrep (SAST), Trivy or
  OSV-Scanner (dependencies and containers), with the JSON outputs saved
  as pipeline artifacts and then published to durable storage (Bitbucket
  artifacts are short-lived; a worked `bitbucket-pipelines.yml` is in
  `templates/bitbucket-pipelines.example.yml`). The report's leg 3 then
  reads those artifacts exactly as it reads native alerts.
- Dependency counts can also come from the language tooling itself in the
  pipeline (`npm audit --json`, `pip-audit`, `cargo audit`), saved the
  same way.
- Activity: repository commits and Pipelines APIs.
- Recommendation shape: if the customer wants native, dashboard-grade
  scanning on Bitbucket, the named options are Snyk or SonarQube Cloud
  as a paid app, or migrating the product repos to GitHub/GitLab. The
  report presents the trade-off (cost, migration effort) and grades the
  pipeline-fallback stack as full coverage while it runs and is read.

## Azure DevOps

- No native Dependabot/CodeQL equivalent in the base product. GitHub
  Advanced Security for Azure DevOps (GHAzDO) adds CodeQL SAST,
  dependency scanning, and secret scanning as a paid per-committer
  add-on; that is the native route.
- Recording GHAzDO in the config: set `code_host_addons: ["ghazdo"]`
  and name the tools `ghazdo-dependency-scanning` / `codeql` /
  `secret-scanning`. The validator accepts the GitHub tool names on
  this host only with the add-on recorded; without it, the same values
  are rejected as the false claim they would be.
- Reading results: GHAzDO alerts live under each repo's Advanced
  Security tab and the Advanced Security REST APIs; pipeline fallback
  results are read from the published build artifacts, exactly as on
  Bitbucket (worked file: `templates/azure-pipelines.example.yml`).
- Without it, the same pipeline fallback stack as Bitbucket, run in
  Azure Pipelines with artifacts published per build.

## Gitea / Codeberg / self-hosted

- No native scanning. Pipeline fallbacks run in the host's CI: Gitea
  Actions (act runners) on Gitea/Forgejo, and Woodpecker CI on
  Codeberg (Codeberg does not run Gitea Actions for all projects; the
  intake records which CI the instance actually has). Renovate
  (self-hosted) covers dependency update PRs; detection counts come
  from OSV-Scanner in CI.

## Any other code host

- The generic contract, by analogy with the edge rule: record the host
  as `other` with a `notes` entry naming it, name the scanners actually
  in place from the recognized vocabulary (the pipeline fallback stack
  is host-agnostic), and read the saved scan outputs as the leg's
  evidence. GitHub service names are rejected on `other` too: an
  unknown host does not get to claim them.

## Every host: the rules that do not change

- A scan that exists but whose results nobody reads is graded as dark.
  The report reads results, not settings pages.
- New and closed counts since the last edition come from the saved
  records of both editions, never from memory.
- A repository where scanning is disabled is named in the edition, every
  edition, until it is not.
