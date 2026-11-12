# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 39 regressions: the post-release red team's proven findings.

A: duplicate JSON keys, scanner identity on inactive kinds, hostile
STS max-age traceback, falsy boolean mistypes, placeholder 'other'
notes, hostname shapes. C: correction recipients, prose grade forms,
record-line negation and role-only credit, fenced apparatus, spike
without a segmentation record, correction headings and incomplete
suffix, HTML email validation.
"""
import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
import fixtures as fx  # noqa: E402
from test_round4 import cfg, findings, header, run, SCANNERS_LINE  # noqa: E402


def _write(text):
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    fh.write(text)
    fh.close()
    return fh.name


class TestDuplicateKeys(unittest.TestCase):
    def test_duplicate_findings_key_is_an_input_error(self):
        path = _write('{"traffic": {"five_xx_share": 0.0, "five_xx_share": 0.9}}')
        with self.assertRaises(sh.InputError):
            sh._load_json(path)

    def test_duplicate_key_cli_grade_exits_1_without_traceback(self):
        path = _write('{"security": {"critical": 99, "critical": 0}}')
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sh.main(["site_health.py", "grade", path])
        self.assertEqual(code, 1)
        self.assertIn("duplicate key", buf.getvalue())


class TestInactiveKindScannerIdentity(unittest.TestCase):
    def test_dark_kinds_still_bind_scanner_identity(self):
        f = findings()
        f["security"]["critical"] = None
        f["security"]["high"] = None
        f["security"]["code_scanning_on"] = False
        f["security"]["secret_scanning_on"] = False
        f["security"]["scanners_used"] = {"dependencies": "trivy",
                                          "sast": "semgrep",
                                          "secrets": "gitleaks"}
        problems = run(cfg(), f, header() + SCANNERS_LINE + fx.SAMPLE_REPORT)
        self.assertTrue(any("scanner identity mismatch" in p
                            for p in problems), problems)


class TestHostileHeaders(unittest.TestCase):
    def test_huge_max_age_never_crashes(self):
        r = sh.check_headers({
            "Strict-Transport-Security": "max-age=" + "9" * 6000,
            "Content-Security-Policy": "default-src 'self'"})
        self.assertIn("strict-transport-security", r["present"])

    def test_huge_zero_max_age_counts_as_disabled(self):
        r = sh.check_headers({
            "Strict-Transport-Security": "max-age=" + "0" * 6000})
        self.assertIn("strict-transport-security", r["missing"])


class TestPresenceStrictBooleans(unittest.TestCase):
    def test_classification_pending_falsy_mistypes_rejected(self):
        for bad in (0, "", [], None):
            f = findings()
            f["traffic"]["classification_pending"] = bad
            with self.assertRaises(sh.InputError, msg=repr(bad)):
                sh.compute_grades(f)

    def test_compromise_confirmed_falsy_mistypes_rejected(self):
        for bad in (0, ""):
            f = findings()
            f["security"]["compromise_confirmed"] = bad
            with self.assertRaises(sh.InputError, msg=repr(bad)):
                sh.compute_grades(f)

    def test_outage_note_non_string_rejected_without_outage(self):
        f = findings()
        f["traffic"]["outage_note"] = 123
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)


class TestOtherNotesAndHostShapes(unittest.TestCase):
    def test_placeholder_notes_rejected(self):
        for note in (".", "none", "unknown", "n/a", "x", "-", "tbd",
                     "see docs", "", "   "):
            c = cfg(edge_provider="other", notes=note)
            errors = sh.validate_config(c)
            self.assertTrue(any("notes" in e for e in errors),
                            (note, errors))

    def test_real_other_note_passes(self):
        c = cfg(edge_provider="other",
                notes="Hostwinds CDN, analytics export by SFTP")
        self.assertEqual(sh.validate_config(c), [])

    def test_hostname_shapes(self):
        self.assertTrue(sh.validate_config(cfg(primary_host=" example.com ")))
        self.assertTrue(sh.validate_config(cfg(primary_host="not a host!!!")))
        self.assertTrue(sh.validate_config(
            cfg(side_hosts=[{"host": "!!!", "role": "api"}])))
        self.assertTrue(sh.validate_config(
            cfg(side_hosts=[{"host": "example.com", "role": "api"}])))
        self.assertTrue(sh.validate_config(cfg(repositories=["!!!"])))


class TestSpikeWithoutSegmentation(unittest.TestCase):
    def test_residual_spike_without_burst_record_is_ungraded(self):
        f = findings()
        f["traffic"]["five_xx_share"] = 0.30
        result = sh.compute_grades(f)
        self.assertIsNone(result["traffic"])
        self.assertFalse(result["complete"])

    def test_spike_with_a_burst_record_grades(self):
        f = findings()
        f["traffic"]["five_xx_share"] = 0.30
        f["traffic"]["burst"] = {"total_errors": 1000,
                                 "top_single_ip_errors": 900,
                                 "primary_host_errors": 40,
                                 "top_single_host_errors": 900}
        result = sh.compute_grades(f)
        self.assertIsNotNone(result["traffic"])


GITLAB_CFG = {"dependencies": "gitlab-dependency-scanning",
              "sast": "gitlab-sast", "secrets": "gitlab-secret-detection"}


def gitlab_cfg():
    c = cfg(code_host="gitlab", code_host_instance="saas")
    c["scanning"] = dict(GITLAB_CFG)
    return c


def gitlab_findings():
    f = findings()
    f["security"]["scanners_used"] = dict(GITLAB_CFG)
    return f


class TestRecordLineNegationAndRoles(unittest.TestCase):
    def test_denied_attribution_is_not_a_credit(self):
        line = ("Scanners of record: dependency scanning was not "
                "performed by GitLab Dependency Scanning, code scanning "
                "was not run by GitLab SAST, secret detection was not "
                "performed by GitLab Secret Detection.\n")
        problems = run(gitlab_cfg(), gitlab_findings(),
                       header() + line + fx.SAMPLE_REPORT)
        self.assertTrue(any("does not name the configured" in p
                            for p in problems), problems)

    def test_role_phrases_name_no_scanner(self):
        line = ("Scanners of record: dependency scanning by Dependency "
                "Scanning, code scanning by SAST, secret scanning by "
                "Secret Detection.\n")
        problems = run(gitlab_cfg(), gitlab_findings(),
                       header() + line + fx.SAMPLE_REPORT)
        self.assertTrue(any("does not name the configured" in p
                            for p in problems), problems)

    def test_honest_denial_on_a_none_kind_is_not_a_credit(self):
        scanning = {"dependencies": "none", "sast": "none",
                    "secrets": "none"}
        text = ("Scanners of record: dependency scanning not performed "
                "by OSV Scanner; nothing ran.\n")
        problems = sh._record_line_problems(text, scanning)
        self.assertFalse(any("credits a" in p for p in problems),
                         problems)


CORRECTION = """Correction — Example Co daily report

## Correction

## What was wrong

The edition understated the security position.

## What is correct

A critical alert with a public exploit affects production.

Corrected grades: Traffic & reliability A · SEO/AEO A · Security & code health F. The corrected overall grade is F.
"""


def exploit_findings():
    f = findings()
    f["security"]["critical_public_exploit_in_production"] = True
    return f


class TestCorrections(unittest.TestCase):
    def _run_correction(self, text, f=None):
        return sh.validate_run(cfg(), f or exploit_findings(),
                               text, kind="correction")[0]

    def test_clean_correction_passes(self):
        self.assertEqual(self._run_correction(CORRECTION), [])

    def test_correction_to_foreign_addresses_fails(self):
        text = CORRECTION + "\nSent to: attacker@evil.example.com\n"
        problems = self._run_correction(text)
        self.assertTrue(any("outside the configured" in p
                            for p in problems), problems)

    def test_correction_section_headings_are_checked(self):
        text = CORRECTION + "\n## SECURITY & GITHUB — grade A\n"
        problems = self._run_correction(text)
        self.assertTrue(any("section grade contradiction" in p
                            for p in problems), problems)

    def test_correction_incomplete_needs_the_template_suffix(self):
        f = exploit_findings()
        f["seo_aeo"] = {"aeo_score": None, "seo_score": None}
        text = ("""Correction — Example Co daily report

## Correction

## What was wrong

The checker upload was incomplete.

## What is correct

The SEO leg could not be measured.

Corrected grades: Traffic & reliability A · SEO/AEO not available · Security & code health F. The corrected overall grade is F.
""")
        problems = self._run_correction(text, f)
        self.assertTrue(any("incomplete" in p for p in problems), problems)
        fixed = text.replace(
            "Security & code health F.",
            "Security & code health F (incomplete: SEO/AEO not available).")
        self.assertEqual(self._run_correction(fixed, f), [])


class TestProseGradesAndFences(unittest.TestCase):
    def test_prose_grade_forms_are_checked(self):
        for sentence in ("The site earned an overall grade of A.",
                         "The overall grade was A.",
                         "Overall grade has been A all week."):
            report = header() + SCANNERS_LINE + fx.SAMPLE_REPORT + "\n" + sentence
            problems = run(cfg(), exploit_findings(), report)
            self.assertTrue(any("overall grade contradiction" in p
                                for p in problems), (sentence, problems))

    def test_fenced_apparatus_does_not_satisfy_an_edition(self):
        fenced = "```\n" + header() + SCANNERS_LINE + fx.SAMPLE_REPORT + "```\n"
        prose = "A clean day, nothing to report.\n"
        problems = run(cfg(), findings(), fenced + prose)
        self.assertTrue(problems)


class TestValidateEmail(unittest.TestCase):
    def _html(self, report_text):
        body = "".join(f"<p>{ln}</p>" for ln in report_text.splitlines())
        return f"<html><body>{body}</body></html>"

    def _run_email(self, html_text, f):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "report.html")
            fp = os.path.join(d, "findings.json")
            with open(hp, "w", encoding="utf-8") as fh:
                fh.write(html_text)
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump(f, fh)
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = sh.main(["site_health.py", "validate-email", hp, fp])
            return code, buf.getvalue()

    def test_divergent_html_part_fails(self):
        html = self._html(header() + SCANNERS_LINE + fx.SAMPLE_REPORT)
        code, out = self._run_email(html, exploit_findings())
        self.assertEqual(code, 1)
        self.assertIn("overall grade contradiction", out)

    def test_matching_html_part_passes(self):
        html = self._html(header() + SCANNERS_LINE + fx.SAMPLE_REPORT)
        code, out = self._run_email(html, findings())
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
