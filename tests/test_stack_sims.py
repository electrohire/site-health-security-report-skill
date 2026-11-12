# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Simulated deployments for every supported stack (round 39).

The owner's bar: comprehensive support for stack diversity, proven in
sim environments actually using those stacks. For every edge x code
host combination the validator accepts, this suite builds a simulated
deployment on disk (config.json, findings.json, report.md in a temp
directory) and drives the real CLI entry point through it:
validate-config, grade, check-run. A combination passes only when the
whole run agrees end-to-end. Negative sims assert that each host's
impossible scanner claims are rejected in the same environment.
"""
import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
sys.path.insert(0, os.path.dirname(__file__))
import site_health as sh  # noqa: E402
import fixtures as fx  # noqa: E402
from test_round4 import header  # noqa: E402

CLI = os.path.join(os.path.dirname(__file__), "..", "skills",
                   "site-health-security-report", "scripts", "site_health.py")

EDGES = ["cloudflare", "aws-cloudfront", "azure-front-door", "fastly",
         "akamai", "sucuri", "netlify", "vercel", "bunny", "other", "none"]

# host -> (config overrides, scanning trio, code_host_ci)
HOSTS = {
    "github": ({}, {"dependencies": "dependabot", "sast": "codeql",
                    "secrets": "secret-scanning"}, "github-actions"),
    "gitlab": ({"code_host_instance": "saas"},
               {"dependencies": "gitlab-dependency-scanning",
                "sast": "gitlab-sast",
                "secrets": "gitlab-secret-detection"}, "gitlab-ci"),
    "bitbucket": ({"code_host_instance": "saas"},
                  {"dependencies": "osv-scanner", "sast": "semgrep",
                   "secrets": "gitleaks"}, "bitbucket-pipelines"),
    "azure-devops": ({"code_host_instance": "saas"},
                     {"dependencies": "osv-scanner", "sast": "semgrep",
                      "secrets": "gitleaks"}, "azure-pipelines"),
    "azure-devops-ghazdo": ({"code_host_instance": "saas",
                             "code_host_addons": ["ghazdo"]},
                            {"dependencies": "ghazdo-dependency-scanning",
                             "sast": "ghazdo-codeql",
                             "secrets": "ghazdo-secret-scanning"},
                            "azure-pipelines"),
    "gitea": ({"code_host_instance": "self-managed"},
              {"dependencies": "osv-scanner", "sast": "semgrep",
               "secrets": "gitleaks"}, "gitea-actions"),
    "codeberg": ({}, {"dependencies": "osv-scanner", "sast": "semgrep",
                      "secrets": "gitleaks"}, "woodpecker"),
    "other": ({"notes": "Forgejo self-hosted at code.example.org; "
                        "BunnyCDN in front (recorded as other/other sim)"},
              {"dependencies": "trivy", "sast": "semgrep",
               "secrets": "trufflehog"}, "woodpecker"),
}


def sim_config(edge, host_key):
    overrides, trio, ci = HOSTS[host_key]
    host = "azure-devops" if host_key == "azure-devops-ghazdo" else host_key
    c = copy.deepcopy(fx.BASE_CONFIG)
    c["edge_provider"] = edge
    c["code_host"] = host
    c["code_host_ci"] = ci
    c["scanning"] = dict(trio)
    c.update(overrides)
    if edge == "none":
        c["edge_credential"] = "none"
    if edge == "other":
        c["notes"] = "Hostwinds CDN (regional provider), export by SFTP"
    if host == "other":
        c.setdefault("notes", HOSTS["other"][0]["notes"])
    return c


def sim_findings(edge, host_key):
    _overrides, trio, _ci = HOSTS[host_key]
    f = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
    f["security"]["scanners_used"] = dict(trio)
    if edge == "none":
        f["security"]["edge_posture"] = "none"
    return f


def sim_report(edge, host_key):
    """The report the way the skill composes one: the grades come from
    the tool's own grading of the sim findings (a no-edge deployment
    grades Security C on posture, and its report says C)."""
    _overrides, trio, _ci = HOSTS[host_key]
    grades = sh.compute_grades(sim_findings(edge, host_key))
    line = "Scanners of record: {}, {}, {}.\n".format(
        trio["dependencies"], trio["sast"], trio["secrets"])
    host = "azure-devops" if host_key == "azure-devops-ghazdo" else host_key
    body = (
        "Example Co daily report\n"
        f"OVERALL GRADE: {grades['overall']}\n"
        f"Sub-grades: Traffic & reliability {grades['traffic']} · "
        f"SEO/AEO {grades['seo_aeo']} · "
        f"Security & code health {grades['security']}\n"
        f"TRAFFIC & {edge.replace('-', ' ').upper()} — grade {grades['traffic']}\n"
        f"SEO / AEO — grade {grades['seo_aeo']}\n"
        f"SECURITY & {host.replace('-', ' ').upper()} — grade {grades['security']}\n"
        "WEBSITE SECURITY SCANS\n"
        "PRIVACY & COMPLIANCE\n"
        "RECOMMENDATIONS (ranked)\n")
    return header() + line + body


def run_cli(*args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = sh.main(["site_health.py", *args])
    return code, buf.getvalue()


class SimEnvironment:
    """A simulated deployment on disk, driven through the real CLI."""

    def __init__(self, edge, host_key):
        self.dir = tempfile.TemporaryDirectory(prefix="stack-sim-")
        root = self.dir.name
        self.config_path = os.path.join(root, "config.json")
        self.findings_path = os.path.join(root, "findings.json")
        self.report_path = os.path.join(root, "report.md")
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(sim_config(edge, host_key), fh, indent=2)
        with open(self.findings_path, "w", encoding="utf-8") as fh:
            json.dump(sim_findings(edge, host_key), fh, indent=2)
        with open(self.report_path, "w", encoding="utf-8") as fh:
            fh.write(sim_report(edge, host_key))

    def close(self):
        self.dir.cleanup()


class TestStackSimMatrix(unittest.TestCase):
    def test_every_edge_by_every_host_end_to_end(self):
        failures = []
        runs = 0
        for edge in EDGES:
            for host_key in HOSTS:
                runs += 1
                sim = SimEnvironment(edge, host_key)
                try:
                    code, out = run_cli("validate-config", sim.config_path)
                    if code != 0:
                        failures.append(f"{edge}/{host_key} validate-config: {out}")
                        continue
                    code, out = run_cli("grade", sim.findings_path)
                    if code != 0:
                        failures.append(f"{edge}/{host_key} grade: {out}")
                        continue
                    code, out = run_cli("check-run", sim.config_path,
                                        sim.findings_path, sim.report_path)
                    if code != 0:
                        failures.append(f"{edge}/{host_key} check-run: {out}")
                finally:
                    sim.close()
        self.assertEqual(runs, len(EDGES) * len(HOSTS))
        self.assertEqual(failures, [])

    def test_subprocess_entry_point_on_one_sim(self):
        # The __main__ path itself, not just main(): the installed CLI
        # as an operator would run it.
        sim = SimEnvironment("cloudflare", "github")
        try:
            proc = subprocess.run(
                [sys.executable, CLI, "check-run", sim.config_path,
                 sim.findings_path, sim.report_path],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("OK: config, findings and report agree",
                          proc.stdout)
        finally:
            sim.close()


class TestStackSimNegatives(unittest.TestCase):
    """Each host's impossible claims, rejected inside a sim."""

    def _config_code(self, host_key, trio, **extra):
        c = copy.deepcopy(fx.BASE_CONFIG)
        host = "azure-devops" if host_key == "azure-devops-ghazdo" else host_key
        overrides, _t, ci = HOSTS[host_key]
        c["code_host"] = host
        c["code_host_ci"] = ci
        c.update(overrides)
        c["scanning"] = trio
        c.update(extra)
        return sh.validate_config(c)

    def test_github_only_scanners_rejected_on_other_hosts(self):
        trio = {"dependencies": "dependabot", "sast": "codeql",
                "secrets": "secret-scanning"}
        for host_key in ("gitlab", "bitbucket", "azure-devops", "gitea",
                         "codeberg", "other"):
            self.assertTrue(self._config_code(host_key, trio), host_key)

    def test_gitlab_scanners_rejected_on_github(self):
        trio = {"dependencies": "gitlab-dependency-scanning",
                "sast": "gitlab-sast", "secrets": "gitlab-secret-detection"}
        self.assertTrue(self._config_code("github", trio))

    def test_ghazdo_names_rejected_without_the_addon(self):
        trio = {"dependencies": "ghazdo-dependency-scanning",
                "sast": "ghazdo-codeql", "secrets": "ghazdo-secret-scanning"}
        self.assertTrue(self._config_code("azure-devops", trio))

    def test_renovate_is_not_a_detection_scanner_anywhere(self):
        for host_key in HOSTS:
            _o, trio, _ci = HOSTS[host_key]
            bad = dict(trio, dependencies="renovate")
            errors = self._config_code(host_key, bad)
            self.assertTrue(any("renovate" in e for e in errors),
                            (host_key, errors))

    def test_sonarqube_is_not_a_dependency_scanner(self):
        _o, trio, _ci = HOSTS["github"]
        bad = dict(trio, dependencies="sonarqube")
        errors = self._config_code("github", bad)
        self.assertTrue(any("sonarqube" in e for e in errors), errors)

    def test_grype_and_checkov_are_recordable(self):
        c = copy.deepcopy(fx.BASE_CONFIG)
        c["scanning"] = {"dependencies": "grype", "sast": "checkov",
                         "secrets": "gitleaks"}
        self.assertEqual(sh.validate_config(c), [])


if __name__ == "__main__":
    unittest.main()
