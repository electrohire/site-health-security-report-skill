# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Unit tests for skills/site-health-security-report/scripts/site_health.py.

Run:  python3 -m unittest discover -s tests -v
Standard library only, matching the tool itself.
"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent /
                       "skills" / "site-health-security-report" / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import site_health as sh  # noqa: E402
import fixtures as fx  # noqa: E402


class TestHeaders(unittest.TestCase):
    def test_full_headers_enforcing(self):
        r = sh.check_headers({
            "Strict-Transport-Security": "max-age=15552000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        })
        self.assertEqual(r["count"], 6)
        self.assertEqual(r["csp"], "enforcing")
        self.assertEqual(r["missing"], [])

    def test_report_only_is_not_enforcing(self):
        r = sh.check_headers({"Content-Security-Policy-Report-Only": "default-src 'self'"})
        self.assertEqual(r["csp"], "report-only")
        self.assertIn("content-security-policy", r["missing"])

    def test_missing_csp(self):
        self.assertEqual(sh.check_headers({})["csp"], "missing")

    def test_case_insensitive_keys(self):
        r = sh.check_headers({"content-security-policy": "default-src 'self'"})
        self.assertEqual(r["csp"], "enforcing")


class TestBurstRule(unittest.TestCase):
    def test_scanner_burst_is_concentrated_event_not_outage(self):
        s = fx.SCANNER_BURST_SEGMENTS
        self.assertEqual(
            sh.classify_error_burst(s["total_errors"], s["top_single_ip_errors"],
                                    s["primary_host_errors"], s["top_single_host_errors"]),
            "concentrated-event")

    def test_real_outage(self):
        s = fx.REAL_OUTAGE_SEGMENTS
        self.assertEqual(
            sh.classify_error_burst(s["total_errors"], s["top_single_ip_errors"],
                                    s["primary_host_errors"], s["top_single_host_errors"]),
            "outage")

    def test_side_host_burst_is_concentrated_even_when_spread(self):
        # Errors spread across many addresses but aimed at one side host
        # (top host = the staging host at 70%): a concentrated event on
        # that host, not a primary outage.
        self.assertEqual(sh.classify_error_burst(1000, 100, 300, 700), "concentrated-event")

    def test_distributed_failure_is_neither_outage_nor_scanner(self):
        s = fx.DISTRIBUTED_FAILURE_SEGMENTS
        self.assertEqual(
            sh.classify_error_burst(s["total_errors"], s["top_single_ip_errors"],
                                    s["primary_host_errors"], s["top_single_host_errors"]),
            "distributed")

    def test_zero_errors_is_not_an_outage(self):
        self.assertEqual(sh.classify_error_burst(0, 0, 0), "distributed")


class TestGrading(unittest.TestCase):
    def test_healthy_github_cloudflare_is_a(self):
        g = sh.compute_grades(fx.HEALTHY_GITHUB_CLOUDFLARE)
        self.assertEqual(g["overall"], "A")

    def test_bitbucket_aws_without_scanning_caps_security_at_c(self):
        g = sh.compute_grades(fx.BITBUCKET_AWS_NO_SCANNING)
        self.assertEqual(g["security"], "C")
        causes = " ".join(g["causes"]["security"])
        self.assertIn("code scanning is dark", causes)
        self.assertIn("secret scanning is dark", causes)
        self.assertIn("report-only", causes)
        self.assertEqual(g["overall"], "C")

    def test_scanner_day_is_not_an_f_and_traffic_not_outage_driven(self):
        # With outage_confirmed correctly False after segmentation, the
        # day grades on its real problems: 404 share and 5xx volume.
        g = sh.compute_grades(fx.SCANNER_BURST_DAY)
        self.assertNotEqual(g["traffic"], "F")
        self.assertEqual(g["overall"], "C")

    def test_confirmed_outage_is_f(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["traffic"]["outage_confirmed"] = True
        day["traffic"]["burst"] = {"total_errors": 1000, "top_single_ip_errors": 100,
                                   "primary_host_errors": 620,
                                   "top_single_host_errors": 620}
        self.assertEqual(sh.compute_grades(day)["traffic"], "F")

    def test_public_exploit_in_production_is_f_security(self):
        g = sh.compute_grades(fx.EXPLOIT_IN_PRODUCTION)
        self.assertEqual(g["security"], "F")
        self.assertEqual(g["overall"], "F")

    def test_critical_without_exploit_caps_at_d(self):
        day = copy.deepcopy(fx.EXPLOIT_IN_PRODUCTION)
        day["security"]["critical_public_exploit_in_production"] = False
        self.assertEqual(sh.compute_grades(day)["security"], "D")

    def test_high_caps_security_at_c(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["high"] = 1
        self.assertEqual(sh.compute_grades(day)["security"], "C")

    def test_missing_dmarc_is_a_named_cause(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["dmarc"] = "none"
        g = sh.compute_grades(day)
        self.assertEqual(g["security"], "C")
        self.assertIn("DMARC", " ".join(g["causes"]["security"]))

    def test_cert_expiring_soon_is_a_named_cause(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["cert_days_left"] = 7
        g = sh.compute_grades(day)
        self.assertEqual(g["security"], "C")

    def test_no_scores_means_no_seo_grade_and_an_incomplete_overall(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["seo_aeo"] = {"aeo_score": None, "seo_score": None}
        g = sh.compute_grades(day)
        self.assertIsNone(g["seo_aeo"])
        # The overall is computed from the graded legs but is flagged
        # incomplete; it must never present as a full A.
        self.assertFalse(g["complete"])
        self.assertEqual(g["ungraded_legs"], ["seo_aeo"])

    def test_score_bands(self):
        for score, want in [(95, "A"), (85, "B"), (75, "C"), (60, "D"), (40, "F")]:
            day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
            day["seo_aeo"] = {"aeo_score": score, "aeo_scan_id": "a1",
                              "seo_score": score, "seo_scan_id": "s1"}
            self.assertEqual(sh.compute_grades(day)["seo_aeo"], want, score)


class TestConfigValidation(unittest.TestCase):
    def test_example_config_template_is_valid(self):
        import json
        path = (Path(__file__).resolve().parent.parent / "skills" /
                "site-health-security-report" / "templates" / "config.example.json")
        cfg = json.loads(path.read_text())
        self.assertEqual(sh.validate_config(cfg), [])

    def test_missing_intake_fields_are_errors(self):
        errors = sh.validate_config({"site_name": "X"})
        self.assertTrue(any("primary_host" in e for e in errors))
        self.assertTrue(any("edge_provider" in e for e in errors))

    def test_unknown_providers_are_rejected_not_assumed(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["edge_provider"] = "some-cdn"
        cfg["code_host"] = "sourcehut"
        errors = sh.validate_config(cfg)
        self.assertTrue(any("edge_provider" in e for e in errors))
        self.assertTrue(any("code_host" in e for e in errors))

    def test_bitbucket_native_sast_claim_is_rejected(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["code_host"] = "bitbucket"
        cfg["scanning"] = {"dependencies": "osv-scanner", "sast": "native",
                           "secrets": "gitleaks"}
        errors = sh.validate_config(cfg)
        self.assertTrue(any("no native SAST" in e for e in errors))

    def test_bitbucket_with_fallback_stack_is_valid(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["code_host"] = "bitbucket"
        cfg["edge_provider"] = "aws-cloudfront"
        cfg["scanning"] = {"dependencies": "osv-scanner", "sast": "semgrep",
                           "secrets": "gitleaks"}
        self.assertEqual(sh.validate_config(cfg), [])

    def test_gitlab_azure_config_is_valid(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["code_host"] = "gitlab"
        cfg["edge_provider"] = "azure-front-door"
        cfg["scanning"] = {"dependencies": "gitlab-dependency-scanning",
                           "sast": "gitlab-sast", "secrets": "gitlab-secret-detection"}
        self.assertEqual(sh.validate_config(cfg), [])

    def test_unrecorded_scan_types_are_errors(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["scanning"] = {"dependencies": "dependabot"}
        errors = sh.validate_config(cfg)
        self.assertTrue(any("scanning.sast" in e for e in errors))
        self.assertTrue(any("scanning.secrets" in e for e in errors))


class TestReportValidation(unittest.TestCase):
    def test_complete_report_with_matching_grade_passes(self):
        self.assertEqual(sh.validate_report(fx.SAMPLE_REPORT, fx.HEALTHY_GITHUB_CLOUDFLARE), [])

    def test_grade_mismatch_is_caught(self):
        bad = fx.SAMPLE_REPORT.replace("OVERALL GRADE: A", "OVERALL GRADE: B")
        problems = sh.validate_report(bad, fx.HEALTHY_GITHUB_CLOUDFLARE)
        self.assertTrue(any("contradiction" in p or "grade mismatch" in p for p in problems))

    def test_missing_section_is_caught(self):
        bad = fx.SAMPLE_REPORT.replace("RECOMMENDATIONS (ranked)", "NOTES")
        problems = sh.validate_report(bad, fx.HEALTHY_GITHUB_CLOUDFLARE)
        self.assertTrue(any("recommendations" in p for p in problems))


class TestRepoHygiene(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent

    def test_every_skill_doc_carries_spdx(self):
        skill_dir = self.ROOT / "skills" / "site-health-security-report"
        for md in skill_dir.rglob("*.md"):
            self.assertIn("SPDX-License-Identifier: MIT", md.read_text(), str(md))

    def test_templates_exist(self):
        t = self.ROOT / "skills" / "site-health-security-report" / "templates"
        for name in ("report-template.md", "report-email.html",
                     "correction-template.md", "evidence-ledger.example.md",
                     "config.example.json", "config.example.yaml",
                     "bitbucket-pipelines.example.yml",
                     "azure-pipelines.example.yml",
                     "gitea-actions.example.yml"):
            self.assertTrue((t / name).exists(), name)

    def test_skill_md_states_the_hard_rules(self):
        text = (self.ROOT / "skills" / "site-health-security-report" / "SKILL.md").read_text()
        for phrase in ("stack intake", "burst rule", "Never invent", "idempotency"):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
