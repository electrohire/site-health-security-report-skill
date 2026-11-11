# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round-3 regression battery: cross-artifact validation (check-run),
burst-record enforcement, score provenance, vendor grade scales, and
the config type-confusion fixes. Each test names the hole it closes."""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "skills", "site-health-security-report",
                                "scripts"))
sys.path.insert(0, os.path.dirname(__file__))
import site_health as sh  # noqa: E402
from fixtures import BASE_CONFIG, HEALTHY_GITHUB_CLOUDFLARE as HEALTHY, SAMPLE_REPORT  # noqa: E402

HEADER = ("From: Example Co Reports <reports@send.example.com> · "
          "To: owner@example.com\n")
SCANNERS_LINE = "Scanners: dependabot, codeql, secret-scanning.\n"


def cfg(**over):
    c = copy.deepcopy(BASE_CONFIG)
    c.update(over)
    return c


def findings(**sec_over):
    f = copy.deepcopy(HEALTHY)
    f["security"]["scanners_used"] = {"dependencies": "dependabot",
                                      "sast": "codeql",
                                      "secrets": "secret-scanning"}
    f["security"].update(sec_over)
    return f


def run_problems(c, f, report):
    return sh.validate_run(c, f, report)[0]


class TestCheckRun(unittest.TestCase):
    def test_consistent_triple_passes(self):
        self.assertEqual(
            run_problems(cfg(), findings(), HEADER + SCANNERS_LINE + SAMPLE_REPORT), [])

    def test_scanning_none_vs_findings_on_is_caught(self):
        c = cfg()
        c["scanning"] = {"dependencies": "osv-scanner", "sast": "none",
                         "secrets": "gitleaks"}
        f = findings(scanners_used={"sast": "codeql", "secrets": "gitleaks"})
        problems = run_problems(c, f, HEADER + SAMPLE_REPORT)
        self.assertTrue(any("scanning.sast" in p for p in problems), problems)

    def test_edge_none_vs_protected_posture_is_caught(self):
        c = cfg(edge_provider="none", edge_credential="none")
        problems = run_problems(c, findings(), HEADER + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("edge_posture" in p for p in problems), problems)

    def test_retyped_recipient_is_caught(self):
        report = HEADER.replace("owner@example.com", "boss-typo@example.org")
        problems = run_problems(cfg(), findings(), report + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("To set" in p for p in problems), problems)

    def test_missing_sender_is_caught(self):
        problems = run_problems(cfg(), findings(), SAMPLE_REPORT)
        self.assertTrue(any("header" in p for p in problems), problems)


class TestBurstRecordEnforcement(unittest.TestCase):
    def test_outage_without_burst_record_is_an_error(self):
        f = findings()
        f["traffic"]["outage_confirmed"] = True
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_outage_claim_contradicted_by_record_is_an_error(self):
        f = findings()
        f["traffic"]["outage_confirmed"] = True
        f["traffic"]["burst"] = {"total_errors": 5214, "top_single_ip_errors": 4800,
                                 "primary_host_errors": 140,
                                 "top_single_host_errors": 4900}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_outage_with_record_grades_f(self):
        f = findings()
        f["traffic"]["outage_confirmed"] = True
        f["traffic"]["burst"] = {"total_errors": 1000, "top_single_ip_errors": 100,
                                 "primary_host_errors": 620,
                                 "top_single_host_errors": 620}
        self.assertEqual(sh.compute_grades(f)["traffic"], "F")

    def test_outage_record_missing_top_host_is_an_error(self):
        f = findings()
        f["traffic"]["outage_confirmed"] = True
        f["traffic"]["burst"] = {"total_errors": 1000, "top_single_ip_errors": 100,
                                 "primary_host_errors": 620}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_swapped_host_fields_are_rejected(self):
        with self.assertRaises(sh.InputError):
            sh.classify_error_burst(2800, 150, 2600, 200)

    def test_threshold_arithmetic_is_integer_exact(self):
        # 599,999,999,999,999,999 / 10^18 is just under 60%: float
        # division rounds it to exactly 0.6 and misclassifies.
        self.assertEqual(
            sh.classify_error_burst(10**18, 599_999_999_999_999_999, 0, 0),
            "distributed")


class TestScoreProvenance(unittest.TestCase):
    def test_score_without_scan_id_is_an_error(self):
        f = findings()
        del f["seo_aeo"]["aeo_scan_id"]
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_seo_b_grade_returns_a_band_cause(self):
        f = findings()
        f["seo_aeo"] = {"aeo_score": 85, "aeo_scan_id": "a1",
                        "seo_score": 85, "seo_scan_id": "s1"}
        grades = sh.compute_grades(f)
        self.assertEqual(grades["seo_aeo"], "B")
        self.assertTrue(grades["causes"]["seo_aeo"])


class TestVendorGradeScales(unittest.TestCase):
    def test_observatory_plus_grades_accepted(self):
        for g in ("B+", "B-", "C+", "D-"):
            grades = sh.compute_grades(findings(observatory_grade=g))
            self.assertIn(grades["security"], ("A", "C"), g)

    def test_observatory_b_minus_does_not_cap_but_does_family_does(self):
        self.assertEqual(sh.compute_grades(
            findings(observatory_grade="B-"))["security"], "A")
        self.assertEqual(sh.compute_grades(
            findings(observatory_grade="D+"))["security"], "C")

    def test_ssl_e_grade_accepted_and_caps(self):
        self.assertEqual(sh.compute_grades(
            findings(ssl_grade="E"))["security"], "C")

    def test_cert_nan_rejected(self):
        with self.assertRaises(sh.InputError):
            sh.compute_grades(findings(cert_days_left=float("nan")))

    def test_null_counts_grade_incomplete_not_clean(self):
        grades = sh.compute_grades(findings(critical=None, high=None))
        self.assertFalse(grades["complete"])
        self.assertIn("alert_counts", grades["unmeasured"])


class TestConfigTypeConfusion(unittest.TestCase):
    def test_null_scanning_is_an_error_not_none(self):
        c = cfg()
        c["scanning"] = {"dependencies": None, "sast": None, "secrets": None}
        errors = sh.validate_config(c)
        self.assertTrue(any("null" in e for e in errors), errors)

    def test_gitlab_vocabulary_rejected_on_github(self):
        c = cfg()
        c["scanning"]["sast"] = "gitlab-sast"
        self.assertTrue(any("GitLab" in e for e in sh.validate_config(c)))

    def test_whitespace_only_required_string_is_empty(self):
        self.assertTrue(any("site_name" in e
                            for e in sh.validate_config(cfg(site_name=" "))))

    def test_addons_as_string_is_an_error(self):
        c = cfg(code_host="azure-devops")
        c["code_host_addons"] = "ghazdo"
        self.assertTrue(any("code_host_addons" in e
                            for e in sh.validate_config(c)))

    def test_unknown_addon_is_an_error(self):
        self.assertTrue(any("code_host_addons" in e
                            for e in sh.validate_config(cfg(
                                code_host_addons=["magic"]))))

    def test_ghazdo_addon_on_wrong_host_is_an_error(self):
        self.assertTrue(any("ghazdo" in e
                            for e in sh.validate_config(cfg(
                                code_host_addons=["ghazdo"]))))

    def test_recipients_cc_must_be_a_list(self):
        c = cfg()
        c["recipients"] = {"to": ["owner@example.com"], "cc": "pal@example.com"}
        self.assertTrue(any("cc" in e for e in sh.validate_config(c)))

    def test_notes_must_be_a_string(self):
        self.assertTrue(any("notes" in e
                            for e in sh.validate_config(cfg(notes=123))))

    def test_underscore_keys_do_not_warn(self):
        c = cfg()
        c["_comment"] = "template note"
        self.assertEqual(sh.validate_config_warnings(c), [])


class TestReportValidationRound3(unittest.TestCase):
    def test_seo_section_flip_is_caught(self):
        report = SAMPLE_REPORT.replace("SEO / AEO — grade A", "SEO / AEO — grade F")
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("seo_aeo" in p for p in problems), problems)

    def test_second_contradictory_subgrades_line_is_caught(self):
        report = SAMPLE_REPORT + \
            "\nSub-grades: Traffic & reliability F · SEO/AEO F · Security & code health F\n"
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("sub-grade" in p for p in problems), problems)

    def test_prose_grade_mention_is_not_a_section_verdict(self):
        report = SAMPLE_REPORT + "\nSecurity & code health grade F would be bad.\n"
        problems = sh.validate_report(report, findings())
        self.assertFalse(any("section grade" in p for p in problems), problems)

    def test_problems_are_not_duplicated(self):
        problems = sh.validate_report("nothing here", findings())
        self.assertEqual(len(problems), len(set(problems)), problems)

    CORRECTION = """CORRECTION — Example Co daily report
What was wrong: the traffic story.
What is correct: a scanner event, not an outage.
Corrected grades: Traffic & reliability A · SEO/AEO A · Security & code health A.
The corrected overall grade is A.
"""

    def test_correction_validates_in_correction_shape(self):
        self.assertEqual(
            sh.validate_report(self.CORRECTION, findings(), kind="correction"), [])

    def test_correction_with_wrong_grade_fails(self):
        bad = self.CORRECTION.replace("grade is A", "grade is F")
        problems = sh.validate_report(bad, findings(), kind="correction")
        self.assertTrue(any("corrected grade" in p for p in problems), problems)

    def test_correction_with_wrong_subgrade_fails(self):
        bad = self.CORRECTION.replace("Traffic & reliability A",
                                      "Traffic & reliability F")
        problems = sh.validate_report(bad, findings(), kind="correction")
        self.assertTrue(any("corrected sub-grade" in p for p in problems), problems)


class TestJsonConstants(unittest.TestCase):
    def test_nan_in_file_is_a_clean_error(self):
        path = os.path.join(os.path.dirname(__file__), "nan_probe.json")
        with self.assertRaises(sh.InputError):
            sh._load_json(path)


if __name__ == "__main__":
    unittest.main()
