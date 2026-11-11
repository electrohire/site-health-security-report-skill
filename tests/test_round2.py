# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round-2 regression battery: the full-stack sandbox simulations and
the second red team (2026-11-10). Each test names the finding it pins.

Run:  python3 -m unittest discover -s tests -v
"""
import copy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "site-health-security-report" / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import site_health as sh  # noqa: E402
import fixtures as fx  # noqa: E402

SCRIPT = ROOT / "skills" / "site-health-security-report" / "scripts" / "site_health.py"


def cfg(**over):
    c = copy.deepcopy(fx.BASE_CONFIG)
    c.update(over)
    return c


class TestScanningVocabulary(unittest.TestCase):
    def test_ghazdo_makes_codeql_legitimate_on_azure_devops(self):
        c = cfg(code_host="azure-devops", code_host_instance="saas",
                code_host_addons=["ghazdo"],
                scanning={"dependencies": "ghazdo-dependency-scanning",
                          "sast": "codeql", "secrets": "secret-scanning"})
        self.assertEqual(sh.validate_config(c), [])

    def test_azure_devops_codeql_without_ghazdo_is_an_error_with_the_fix_named(self):
        c = cfg(code_host="azure-devops", code_host_instance="saas",
                scanning={"dependencies": "osv-scanner", "sast": "codeql",
                          "secrets": "gitleaks"})
        self.assertTrue(any("ghazdo" in e for e in sh.validate_config(c)))

    def test_ghazdo_values_without_the_addon_are_rejected(self):
        c = cfg(code_host="azure-devops", code_host_instance="saas",
                scanning={"dependencies": "ghazdo-dependency-scanning",
                          "sast": "semgrep", "secrets": "gitleaks"})
        self.assertTrue(sh.validate_config(c))

    def test_gitlab_claiming_github_services_is_rejected(self):
        c = cfg(code_host="gitlab", code_host_instance="saas",
                scanning={"dependencies": "dependabot", "sast": "codeql",
                          "secrets": "secret-scanning"})
        self.assertEqual(len(sh.validate_config(c)), 3)

    def test_other_host_claiming_github_services_is_rejected(self):
        c = cfg(code_host="other", notes="Forgejo self-hosted",
                scanning={"dependencies": "dependabot", "sast": "codeql",
                          "secrets": "secret-scanning"})
        self.assertTrue(sh.validate_config(c))

    def test_nonsense_scanner_names_are_rejected_on_any_host(self):
        c = cfg(scanning={"dependencies": "magic-scan", "sast": "magic-sast",
                          "secrets": "magic-secrets"})
        self.assertEqual(len(sh.validate_config(c)), 3)

    def test_brand_prefixed_names_do_not_evade(self):
        c = cfg(code_host="bitbucket",
                scanning={"dependencies": "github-dependabot", "sast": "semgrep",
                          "secrets": "gitleaks"})
        self.assertTrue(sh.validate_config(c))


class TestConfigCompleteness2(unittest.TestCase):
    def test_other_provider_requires_a_note(self):
        c = cfg(edge_provider="other")
        self.assertTrue(any("notes" in e for e in sh.validate_config(c)))
        c["notes"] = "RegionalCDN, homegrown"
        self.assertEqual(sh.validate_config(c), [])

    def test_code_host_instance_is_validated(self):
        c = cfg(code_host="gitlab", code_host_instance="banana")
        self.assertTrue(any("code_host_instance" in e for e in sh.validate_config(c)))

    def test_recipients_must_be_real_addresses(self):
        for bad in ("a@b.co", [""], []):
            c = cfg(recipients={"to": bad, "cc": []})
            self.assertTrue(sh.validate_config(c), bad)

    def test_no_edge_with_edge_credential_warns(self):
        c = cfg(edge_provider="none",
                edge_credential="vault entry 'x/cloudflare'")
        self.assertTrue(any("credential" in w
                            for w in sh.validate_config_warnings(c)))


class TestEdgePosture(unittest.TestCase):
    def test_no_edge_caps_security_at_c(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["edge_posture"] = "none"
        g = sh.compute_grades(day)
        self.assertEqual(g["security"], "C")
        self.assertTrue(any("no edge" in c for c in g["causes"]["security"]))

    def test_cdn_only_caps_security_at_c(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["edge_posture"] = "cdn-only"
        self.assertEqual(sh.compute_grades(day)["security"], "C")

    def test_missing_edge_posture_is_an_input_error(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        del day["security"]["edge_posture"]
        with self.assertRaises(sh.InputError):
            sh.compute_grades(day)


class TestUnmeasuredEvidence(unittest.TestCase):
    def test_null_scans_make_the_run_incomplete_not_clean(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["ssl_grade"] = None
        g = sh.compute_grades(day)
        self.assertFalse(g["complete"])
        self.assertIn("ssl_grade", g["unmeasured"])

    def test_numeric_observatory_score_is_an_input_error(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["observatory_grade"] = 75
        with self.assertRaises(sh.InputError):
            sh.compute_grades(day)


class TestTolerantEnums(unittest.TestCase):
    def test_raw_dmarc_record_is_read_for_its_policy(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["dmarc"] = "v=DMARC1; p=none; rua=mailto:d@example.com"
        g = sh.compute_grades(day)
        self.assertEqual(g["security"], "C")

    def test_csp_underscore_variant_is_read(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["security"]["csp"] = "report_only"
        self.assertEqual(sh.compute_grades(day)["security"], "C")


class TestReportValidationV3(unittest.TestCase):
    def test_footnote_mention_does_not_save_a_wrong_headline(self):
        bad = fx.SAMPLE_REPORT.replace("OVERALL GRADE: A", "OVERALL GRADE: F")
        bad += "\n(An earlier draft said overall grade: a; superseded.)"
        problems = sh.validate_report(bad, fx.HEALTHY_GITHUB_CLOUDFLARE)
        self.assertTrue(any("contradiction" in p for p in problems))

    def test_second_contradictory_overall_line_is_caught(self):
        bad = fx.SAMPLE_REPORT + "\nOVERALL GRADE: B"
        problems = sh.validate_report(bad, fx.HEALTHY_GITHUB_CLOUDFLARE)
        self.assertTrue(any("contradiction" in p for p in problems))

    def test_section_grade_contradiction_is_caught(self):
        bad = fx.SAMPLE_REPORT.replace("TRAFFIC & CLOUDFLARE — grade A",
                                       "TRAFFIC & CLOUDFLARE — grade F")
        problems = sh.validate_report(bad, fx.HEALTHY_GITHUB_CLOUDFLARE)
        self.assertTrue(any("section grade contradiction" in p for p in problems))

    def test_prose_mentions_do_not_form_a_subgrades_line(self):
        bad = fx.SAMPLE_REPORT.replace(
            "Sub-grades: Traffic & reliability A · SEO/AEO A · Security & code health A",
            "Keep traffic & reliability A, seo/aeo A, security & code health A please.")
        problems = sh.validate_report(bad, fx.HEALTHY_GITHUB_CLOUDFLARE)
        self.assertTrue(any("Sub-grades line" in p for p in problems))

    def test_incomplete_must_be_presented_as_incomplete(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["seo_aeo"] = {"aeo_score": None, "seo_score": None}
        problems = sh.validate_report(fx.SAMPLE_REPORT + "\nSEO not available.", day)
        self.assertTrue(any("incomplete" in p for p in problems))

    def test_no_findings_mode_says_what_it_checked(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write(fx.SAMPLE_REPORT)
            path = fh.name
        try:
            r = subprocess.run([sys.executable, str(SCRIPT), "validate-report", path],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0)
            self.assertIn("structure only", r.stdout)
        finally:
            os.unlink(path)


class TestHeaderEdgeCases2(unittest.TestCase):
    def test_none_header_value_is_not_enforcing(self):
        r = sh.check_headers({"Content-Security-Policy": None})
        self.assertEqual(r["csp"], "missing")

    def test_hsts_without_max_age_counts_as_missing(self):
        r = sh.check_headers({"Strict-Transport-Security": "includeSubDomains"})
        self.assertIn("strict-transport-security", r["missing"])

    def test_malformed_url_is_a_clean_cli_error(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "headers", "https://[::1"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)


class TestOutageCauses(unittest.TestCase):
    def test_outage_day_keeps_the_repeated_problems_cause(self):
        day = copy.deepcopy(fx.HEALTHY_GITHUB_CLOUDFLARE)
        day["traffic"]["outage_confirmed"] = True
        day["traffic"]["burst"] = {"total_errors": 1000, "top_single_ip_errors": 100,
                                   "primary_host_errors": 620,
                                   "top_single_host_errors": 620}
        day["traffic"]["repeated_reliability_problems"] = True
        g = sh.compute_grades(day)
        self.assertEqual(g["traffic"], "F")
        self.assertEqual(len(g["causes"]["traffic"]), 2)


if __name__ == "__main__":
    unittest.main()
