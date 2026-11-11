# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Hardening tests: the red-team regression battery (round 1).

Every test here exists because an adversarial pass (scenario testers +
red team, 2026-11-10) proved the defect against the first build. If one
of these fails, the corresponding published claim is false again.

Run:  python3 -m unittest discover -s tests -v
"""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "site-health-security-report" / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import site_health as sh  # noqa: E402
import fixtures as fx  # noqa: E402

SCRIPT = ROOT / "skills" / "site-health-security-report" / "scripts" / "site_health.py"


def run_cli(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=30)


class TestStrictFindings(unittest.TestCase):
    def test_string_false_does_not_manufacture_an_outage(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["traffic"]["outage_confirmed"] = "false"
        with self.assertRaises(sh.InputError):
            sh.compute_grades(day)

    def test_string_false_does_not_manufacture_an_exploit_f(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["critical_public_exploit_in_production"] = "false"
        with self.assertRaises(sh.InputError):
            sh.compute_grades(day)

    def test_missing_security_measurements_are_errors_not_an_a(self):
        with self.assertRaises(sh.InputError):
            sh.compute_grades({"traffic": {"five_xx_share": 0.0, "four_04_share": 0.0,
                                           "outage_confirmed": False},
                               "security": {}})

    def test_empty_findings_are_an_error(self):
        with self.assertRaises(sh.InputError):
            sh.compute_grades({})

    def test_findings_without_privacy_key_do_not_crash(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        del day["security"]["privacy_failures"]
        self.assertEqual(sh.compute_grades(day)["security"], "A")

    def test_share_above_one_is_rejected(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["traffic"]["five_xx_share"] = 1.5
        with self.assertRaises(sh.InputError):
            sh.compute_grades(day)

    def test_score_above_100_is_rejected(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["seo_aeo"]["seo_score"] = 150
        with self.assertRaises(sh.InputError):
            sh.compute_grades(day)

    def test_negative_count_is_rejected(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["critical"] = -1
        with self.assertRaises(sh.InputError):
            sh.compute_grades(day)

    def test_lowercase_grades_still_downgrade(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["observatory_grade"] = "d"
        day["security"]["dmarc"] = "NONE"
        g = sh.compute_grades(day)
        self.assertEqual(g["security"], "C")

    def test_expired_certificate_wording(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["cert_days_left"] = -60
        causes = " ".join(sh.compute_grades(day)["causes"]["security"])
        self.assertIn("expired", causes)
        self.assertNotIn("expires within", causes)

    def test_traffic_b_names_its_cause(self):
        day = copy.deepcopy(fx.BITBUCKET_AWS_NO_SCANNING)
        g = sh.compute_grades(day)
        self.assertEqual(g["traffic"], "B")
        self.assertTrue(g["causes"]["traffic"])


class TestHeaderValues(unittest.TestCase):
    def test_empty_csp_value_is_missing_not_enforcing(self):
        self.assertEqual(sh.check_headers({"Content-Security-Policy": ""})["csp"], "missing")

    def test_hsts_max_age_zero_is_disabled(self):
        r = sh.check_headers({"Strict-Transport-Security": "max-age=0"})
        self.assertIn("strict-transport-security", r["missing"])
        self.assertTrue(r["notes"])

    def test_worthless_full_set_does_not_score_six(self):
        r = sh.check_headers({
            "Strict-Transport-Security": "max-age=0",
            "Content-Security-Policy": "",
            "X-Frame-Options": "", "X-Content-Type-Options": "",
            "Referrer-Policy": "", "Permissions-Policy": "",
        })
        self.assertEqual(r["count"], 0)


class TestBurstValidation(unittest.TestCase):
    def test_impossible_segments_are_rejected(self):
        with self.assertRaises(sh.InputError):
            sh.classify_error_burst(100, 250, 0)

    def test_primary_host_single_ip_attack_is_concentrated(self):
        # One address hammering even the primary host is an attack
        # event, reported as such, not a silent "outage".
        self.assertEqual(sh.classify_error_burst(1000, 700, 900, 900), "concentrated-event")


class TestConfigHardening(unittest.TestCase):
    def test_case_variants_of_native_are_caught(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["code_host"] = "bitbucket"
        cfg["scanning"] = {"dependencies": "osv-scanner", "sast": "Native",
                           "secrets": "gitleaks"}
        self.assertTrue(sh.validate_config(cfg))

    def test_bitbucket_dependabot_and_secret_scanning_claims_are_caught(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["code_host"] = "bitbucket"
        cfg["scanning"] = {"dependencies": "dependabot", "sast": "semgrep",
                           "secrets": "secret-scanning"}
        errors = " ".join(sh.validate_config(cfg))
        self.assertIn("Dependabot", errors)
        self.assertIn("secret scanning", errors)

    def test_missing_hosting_and_staging_are_errors(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        del cfg["hosting"]
        del cfg["staging"]
        errors = " ".join(sh.validate_config(cfg))
        self.assertIn("hosting", errors)
        self.assertIn("staging", errors)

    def test_empty_recipients_are_an_error(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["recipients"] = {"to": [], "cc": []}
        self.assertTrue(sh.validate_config(cfg))

    def test_bad_timezone_is_an_error(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["timezone"] = "Not/AZone"
        self.assertTrue(any("timezone" in e for e in sh.validate_config(cfg)))

    def test_unknown_keys_warn_but_do_not_fail(self):
        cfg = copy.deepcopy(fx.BASE_CONFIG)
        cfg["code_host_instance"] = "self-managed"
        cfg["surprise_key"] = 1
        self.assertEqual(sh.validate_config(cfg), [])
        self.assertTrue(any("surprise_key" in w
                            for w in sh.validate_config_warnings(cfg)))


class TestReportSubgrades(unittest.TestCase):
    def test_subgrade_mismatch_is_caught(self):
        bad = fx.SAMPLE_REPORT.replace("Security & code health A",
                                       "Security & code health F")
        problems = sh.validate_report(bad, fx.HEALTHY_GITHUB_CLOUDFLARE)
        self.assertTrue(any("sub-grade mismatch" in p for p in problems))

    def test_non_github_section_heading_passes(self):
        report = fx.SAMPLE_REPORT.replace("SECURITY & GITHUB", "SECURITY & BITBUCKET")
        self.assertEqual(sh.validate_report(report, fx.HEALTHY_GITHUB_CLOUDFLARE), [])

    def test_ungraded_leg_must_be_said_not_available(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["seo_aeo"] = {"aeo_score": None, "seo_score": None}
        problems = sh.validate_report(fx.SAMPLE_REPORT, day)
        self.assertTrue(any("not available" in p for p in problems))


class TestCliRobustness(unittest.TestCase):
    def test_malformed_json_is_a_clean_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        r = run_cli("grade", path)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ERROR:", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_missing_file_is_a_clean_error(self):
        r = run_cli("grade", "/tmp/definitely-not-here-12345.json")
        self.assertEqual(r.returncode, 1)
        self.assertIn("ERROR:", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_yaml_config_gets_a_clean_explanation(self):
        r = run_cli("validate-config", str(
            ROOT / "skills" / "site-health-security-report" / "templates" / "config.example.yaml"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("config of record", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_validate_config_success_is_not_silent(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(fx.BASE_CONFIG, fh)
            path = fh.name
        r = run_cli("validate-config", path)
        self.assertEqual(r.returncode, 0)
        self.assertIn("OK:", r.stdout)

    def test_headers_rejects_a_non_url_cleanly(self):
        r = run_cli("headers", "ftp://example.com")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
