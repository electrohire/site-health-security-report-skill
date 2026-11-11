# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round-4 regression battery: exact header address sets, scanner
identity, heading-shape coverage, and check-run warning surfacing."""
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

SENDER = "Example Co Reports <reports@send.example.com>"
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


def header(to="owner@example.com", cc=None, sender=SENDER):
    line = f"From: {sender} · To: {to}"
    if cc is not None:
        line += f" · Cc: {cc}"
    return line + "\n"


def run(c, f, report):
    return sh.validate_run(c, f, report)[0]


class TestHeaderExactSets(unittest.TestCase):
    def test_exact_header_passes(self):
        self.assertEqual(run(cfg(), findings(),
                             header() + SCANNERS_LINE + SAMPLE_REPORT), [])

    def test_to_cc_swap_is_caught(self):
        c = cfg()
        c["recipients"] = {"to": ["owner@example.com"], "cc": ["pal@example.com"]}
        report = header(to="pal@example.com", cc="owner@example.com")
        problems = run(c, findings(), report + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("To set" in p for p in problems), problems)

    def test_added_recipient_is_caught(self):
        report = header(to="owner@example.com, attacker@evil.example")
        problems = run(cfg(), findings(), report + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("To set" in p for p in problems), problems)

    def test_address_in_body_prose_does_not_satisfy_the_header(self):
        report = header(to="boss-typo@example.org") + \
            "Signed, owner@example.com\n" + SCANNERS_LINE + SAMPLE_REPORT
        problems = run(cfg(), findings(), report)
        self.assertTrue(any("To set" in p for p in problems), problems)

    def test_unconfigured_cc_is_caught(self):
        report = header(cc="pal@example.com")
        problems = run(cfg(), findings(), report + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("Cc set" in p for p in problems), problems)


class TestScannerIdentity(unittest.TestCase):
    def test_findings_naming_a_different_scanner_is_caught(self):
        f = findings()
        f["security"]["scanners_used"]["sast"] = "semgrep"
        problems = run(cfg(), f, header() + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("scanner identity" in p for p in problems), problems)

    def test_scanning_on_without_scanners_used_is_caught(self):
        f = findings()
        del f["security"]["scanners_used"]
        problems = run(cfg(), f, header() + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("scanners_used" in p for p in problems), problems)

    def test_report_crediting_only_another_scanner_is_caught(self):
        report = header() + "Code scanning (Semgrep) ran clean.\n" + SAMPLE_REPORT
        problems = run(cfg(), findings(), report)
        self.assertTrue(any("never names" in p for p in problems), problems)

    def test_display_name_forms_satisfy_the_naming_check(self):
        c = cfg(code_host="gitlab", code_host_instance="saas")
        c["scanning"] = {"dependencies": "gitlab-dependency-scanning",
                         "sast": "gitlab-sast",
                         "secrets": "gitlab-secret-detection"}
        f = findings()
        f["security"]["scanners_used"] = {
            "dependencies": "gitlab-dependency-scanning",
            "sast": "gitlab-sast", "secrets": "gitlab-secret-detection"}
        report = header() + SAMPLE_REPORT + (
            "\nDependency scanning by GitLab Dependency Scanning; code "
            "scanning (GitLab SAST): on; secret scanning (GitLab Secret "
            "Detection): on.\n")
        self.assertEqual(run(c, f, report), [])


class TestHeadingShapes(unittest.TestCase):
    def test_hyphen_heading_flip_is_caught(self):
        report = SAMPLE_REPORT.replace("TRAFFIC & CLOUDFLARE — grade A",
                                       "TRAFFIC & CLOUDFLARE - grade F")
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("traffic" in p for p in problems), problems)

    def test_html_heading_flip_is_caught(self):
        report = SAMPLE_REPORT + "\n<h2>SECURITY & GITHUB — grade F</h2>\n"
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("security" in p for p in problems), problems)


class TestCheckRunWarnings(unittest.TestCase):
    def test_config_warnings_are_returned(self):
        c = cfg(edge_credential="none")
        _problems, warnings = sh.validate_run(
            c, findings(), header() + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("edge_credential" in w for w in warnings), warnings)


class TestCorrectionTemplateShape(unittest.TestCase):
    def test_filled_shipped_template_validates(self):
        path = os.path.join(os.path.dirname(__file__), "..", "skills",
                            "site-health-security-report", "templates",
                            "correction-template.md")
        text = open(path).read()
        text = text.replace("{{brand.display_name}}", "Example Co")
        text = text.replace("{{date_short}}", "Nov 10")
        text = text.replace("{{short_reason}}", "traffic reading")
        text = text.replace("{{date}}", "November 10, 2026")
        text = text.replace("{{covering_date}}", "November 9, 2026")
        text = text.replace("{{traffic_grade}}", "A")
        text = text.replace("{{seo_grade}}", "A")
        text = text.replace("{{security_grade}}", "A")
        text = text.replace("{{corrected_overall}}", "A")
        text = text.replace("{{sent_overall}}", "F")
        text = text.replace("{{process_fix}}", "the burst record is now mandatory")
        import re
        text = re.sub(r"\{\{[^}]*\}\}", "Detail recorded in the evidence ledger.", text)
        self.assertEqual(
            sh.validate_report(text, findings(), kind="correction"), [])


def _filled_correction():
    import re as _re
    path = os.path.join(os.path.dirname(__file__), "..", "skills",
                        "site-health-security-report", "templates",
                        "correction-template.md")
    t = open(path).read()
    for k, v in {"{{brand.display_name}}": "Example Co", "{{date_short}}": "Nov 10",
                 "{{short_reason}}": "traffic reading", "{{date}}": "November 10, 2026",
                 "{{covering_date}}": "November 9, 2026", "{{traffic_grade}}": "A",
                 "{{seo_grade}}": "A", "{{security_grade}}": "A",
                 "{{corrected_overall}}": "A", "{{sent_overall}}": "F",
                 "{{process_fix}}": "the burst record is now mandatory"}.items():
        t = t.replace(k, v)
    return _re.sub(r"\{\{[^}]*\}\}", "Detail recorded in the evidence ledger.", t)


class TestRound5Shapes(unittest.TestCase):
    def test_correction_passes_check_run_without_header(self):
        problems, _w = sh.validate_run(cfg(), findings(), _filled_correction(),
                                       kind="correction")
        self.assertEqual(problems, [])

    def test_ungraded_leg_edition_validates_with_not_available(self):
        f = findings()
        f["seo_aeo"] = {"aeo_score": None, "seo_score": None}
        report = SAMPLE_REPORT.replace(
            "Sub-grades: Traffic & reliability A · SEO/AEO A · Security & code health A",
            "Sub-grades: Traffic & reliability A · SEO/AEO not available · Security & code health A")
        report = report.replace(
            "OVERALL GRADE: A",
            "OVERALL GRADE: A (incomplete: SEO/AEO not available)")
        report = report.replace("SEO / AEO — grade A", "SEO / AEO — not available")
        self.assertEqual(sh.validate_report(report, f), [])

    def test_dependencies_identity_mismatch_is_caught(self):
        f = findings()
        f["security"]["scanners_used"]["dependencies"] = "osv-scanner"
        problems = run(cfg(), f, header() + SCANNERS_LINE + SAMPLE_REPORT)
        self.assertTrue(any("scanner identity" in p for p in problems), problems)

    def test_block_style_header_parses(self):
        block = "From: " + SENDER + "\nTo:\nowner@example.com\n"
        self.assertEqual(run(cfg(), findings(), block + SCANNERS_LINE + SAMPLE_REPORT), [])

    def test_attributed_html_heading_flip_is_caught(self):
        report = SAMPLE_REPORT + '\n<h2 class="hdr">SECURITY & GITHUB — grade F</h2>\n'
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("security" in p for p in problems), problems)

    def test_separatorless_heading_flip_is_caught(self):
        report = SAMPLE_REPORT + "\nTRAFFIC & CLOUDFLARE grade F\n"
        problems = sh.validate_report(report, findings())
        self.assertTrue(any("traffic" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
