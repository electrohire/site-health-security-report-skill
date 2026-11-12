# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Coverage closure (round 39): every line of site_health.py exercised.

The stack sims cover the happy paths end-to-end; this battery covers
the error and edge branches they do not reach: strict input errors in
the findings validator and graders, config shape errors, correction
validation branches, header/record-line internals, the fetch path
(mocked transport), and every CLI subcommand branch in main(),
including the __main__ guard via runpy.
"""
import contextlib
import copy
import io
import json
import os
import runpy
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
import fixtures as fx  # noqa: E402
from test_round4 import cfg, findings, header, run, SCANNERS_LINE  # noqa: E402

CLI_PATH = os.path.join(os.path.dirname(__file__), "..", "skills",
                        "site-health-security-report", "scripts",
                        "site_health.py")


def call_main(*args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = sh.main(["site_health.py", *args])
    return code, buf.getvalue()


def tmp_file(content, suffix=".json"):
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    fh.write(content)
    fh.close()
    return fh.name


class TestNormEdges(unittest.TestCase):
    def test_csp_none_and_synonyms(self):
        self.assertIsNone(sh._norm_csp(None))
        self.assertEqual(sh._norm_csp("none"), "missing")
        self.assertEqual(sh._norm_csp("absent"), "missing")
        self.assertEqual(sh._norm_csp("banana"), "banana")

    def test_dmarc_none_and_unparseable_record(self):
        self.assertIsNone(sh._norm_dmarc(None))
        raw = "v=DMARC1; rua=mailto:dmarc@example.com"
        self.assertEqual(sh._norm_dmarc(raw), raw.lower())


class TestFetchHeaders(unittest.TestCase):
    def test_non_url_rejected(self):
        with self.assertRaises(sh.InputError):
            sh.fetch_headers("ftp://example.com")

    def test_success_path_with_mocked_transport(self):
        class Resp:
            headers = {"Content-Security-Policy": "default-src 'self'"}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch.object(sh.urllib.request, "urlopen",
                               return_value=Resp()):
            got = sh.fetch_headers("https://example.com")
        self.assertEqual(got, {"Content-Security-Policy": "default-src 'self'"})

    def test_http_error_returns_its_headers(self):
        err = urllib.error.HTTPError(
            "https://example.com", 503, "err", {"X-Test": "1"}, None)
        with mock.patch.object(sh.urllib.request, "urlopen", side_effect=err):
            self.assertEqual(sh.fetch_headers("https://example.com"),
                             {"X-Test": "1"})

    def test_url_error_becomes_input_error(self):
        err = urllib.error.URLError("no route")
        with mock.patch.object(sh.urllib.request, "urlopen", side_effect=err):
            with self.assertRaises(sh.InputError):
                sh.fetch_headers("https://example.com")


class TestBurstAndFindingsValidation(unittest.TestCase):
    def test_burst_negative_count_rejected(self):
        with self.assertRaises(sh.InputError):
            sh.classify_error_burst(-1, 0, 0)

    def test_burst_record_must_be_an_object(self):
        f = findings()
        f["traffic"]["burst"] = "a string"
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_burst_record_missing_key(self):
        f = findings()
        f["traffic"]["burst"] = {"total_errors": 10}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_findings_must_be_an_object(self):
        with self.assertRaises(sh.InputError):
            sh.compute_grades(["not", "a", "dict"])

    def test_findings_section_must_be_an_object(self):
        with self.assertRaises(sh.InputError):
            sh.compute_grades({"traffic": "x"})

    def test_security_section_missing(self):
        f = findings()
        del f["security"]
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_bad_csp_and_dmarc_values(self):
        f = findings()
        f["security"]["csp"] = "sometimes"
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)
        f = findings()
        f["security"]["dmarc"] = "strict"
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_platform_shape_errors(self):
        f = findings()
        f["security"]["platform"] = "wordpress"
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)
        f = findings()
        f["security"]["platform"] = {"source": "wp", "critical": "many",
                                     "high": 0}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_security_count_type_errors(self):
        for key, bad in (("privacy_failures", -1), ("secret_alerts_open", -1),
                         ("ci_blocked", "yes"), ("site_backups_verified", "yes")):
            f = findings()
            f["security"][key] = bad
            with self.assertRaises(sh.InputError, msg=key):
                sh.compute_grades(f)


class TestTrafficGradingBranches(unittest.TestCase):
    def test_outage_with_empty_note_rejected(self):
        f = findings()
        f["traffic"]["outage_confirmed"] = True
        f["traffic"]["outage_note"] = ""
        f["traffic"]["burst"] = {"total_errors": 100,
                                 "top_single_ip_errors": 10,
                                 "primary_host_errors": 90,
                                 "top_single_host_errors": 90}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_share_in_c_band_caps_at_c(self):
        f = findings()
        f["traffic"]["five_xx_share"] = 0.01
        f["traffic"]["burst"] = {"total_errors": 100,
                                 "top_single_ip_errors": 90,
                                 "primary_host_errors": 5,
                                 "top_single_host_errors": 90}
        result = sh.compute_grades(f)
        self.assertEqual(result["traffic"], "C")
        self.assertTrue(any("server errors were 1.0%" in c
                            for c in result["causes"]["traffic"]))

    def test_repeated_reliability_caps_at_d(self):
        f = findings()
        f["traffic"]["repeated_reliability_problems"] = True
        result = sh.compute_grades(f)
        self.assertEqual(result["traffic"], "D")

    def test_side_host_outage_shapes(self):
        f = findings()
        f["traffic"]["side_host_outage"] = "api.example.com"
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)
        f = findings()
        f["traffic"]["side_host_outage"] = {"host": "api.example.com",
                                            "note": 42}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)


class TestConfigShapeBranches(unittest.TestCase):
    def test_config_must_be_an_object(self):
        errors, _w = sh._validate_config(["not", "a", "dict"])
        self.assertTrue(any("JSON object" in e for e in errors))

    def test_codeberg_gitea_actions_ci_warning(self):
        c = cfg(code_host="codeberg", code_host_ci="gitea-actions")
        c["scanning"] = {"dependencies": "osv-scanner", "sast": "semgrep",
                         "secrets": "gitleaks"}
        warnings = sh.validate_config_warnings(c)
        self.assertTrue(any("gitea-actions" in w for w in warnings),
                        warnings)

    def test_side_host_entry_without_host_is_bad(self):
        c = cfg(side_hosts=[{"role": "api"}])
        self.assertTrue(any("side_hosts" in e
                            for e in sh.validate_config(c)))

    def test_brand_must_be_an_object(self):
        self.assertTrue(any("brand must be an object" in e
                            for e in sh.validate_config(cfg(brand="Acme"))))

    def test_brand_display_name_required(self):
        self.assertTrue(any("display_name is required" in e
                            for e in sh.validate_config(cfg(brand={}))))

    def test_side_host_role_must_be_a_string(self):
        c = cfg(side_hosts=[{"host": "api.example.com", "role": 7}])
        self.assertTrue(any("role must be a string" in e
                            for e in sh.validate_config(c)))

    def test_staging_values_must_be_strings(self):
        c = cfg(staging={"url": 42})
        self.assertTrue(any("staging values" in e
                            for e in sh.validate_config(c)))


class TestCorrectionBranches(unittest.TestCase):
    def test_correction_missing_sections_and_lines(self):
        problems = sh.validate_report("a short note", findings(),
                                      kind="correction")
        self.assertTrue(any("missing correction section" in p
                            for p in problems), problems)
        self.assertTrue(any("corrected overall grade is X" in p
                            for p in problems), problems)
        self.assertTrue(any("Corrected grades:" in p for p in problems),
                        problems)

    def test_correction_heading_against_ungraded_leg(self):
        f = findings()
        f["seo_aeo"] = {"aeo_score": None, "seo_score": None}
        text = ("## Correction\n\n## What was wrong\n\nx\n\n"
                "## What is correct\n\ny\n\n"
                "## SEO / AEO — grade A\n"
                "Corrected grades: Traffic & reliability A · SEO/AEO not "
                "available · Security & code health A "
                "(incomplete: SEO/AEO not available). "
                "The corrected overall grade is A.\n")
        problems = sh.validate_report(text, f, kind="correction")
        self.assertTrue(any("ungraded" in p for p in problems), problems)


class TestValidateReportAndRunBranches(unittest.TestCase):
    def test_structure_only_without_overall_line(self):
        problems = sh.validate_report("TRAFFIC\nSEO\n", None)
        self.assertTrue(any("missing 'OVERALL GRADE:' line" in p
                            for p in problems), problems)

    def test_validate_run_surfaces_findings_input_errors(self):
        f = findings()
        del f["traffic"]
        problems, _w = sh.validate_run(cfg(), f, fx.SAMPLE_REPORT)
        self.assertTrue(any(p.startswith("findings:") for p in problems),
                        problems)

    def test_secrets_none_contradiction(self):
        c = cfg()
        c["scanning"] = {"dependencies": "dependabot", "sast": "codeql",
                         "secrets": "none"}
        f = findings()
        f["security"]["secret_scanning_on"] = True
        f["security"]["scanners_used"] = {"dependencies": "dependabot",
                                          "sast": "codeql"}
        problems = run(c, f, header() + SCANNERS_LINE + fx.SAMPLE_REPORT)
        self.assertTrue(any("scanning.secrets is 'none'" in p
                            for p in problems), problems)

    def test_scanners_used_must_be_an_object(self):
        f = findings()
        f["security"]["scanners_used"] = "dependabot"
        problems = run(cfg(), f, header() + SCANNERS_LINE + fx.SAMPLE_REPORT)
        self.assertTrue(any("scanners_used must be an object" in p
                            for p in problems), problems)

    def test_edge_posture_contradiction_both_directions(self):
        f = findings()
        f["security"]["edge_posture"] = "none"
        problems = run(cfg(), f, header() + SCANNERS_LINE + fx.SAMPLE_REPORT)
        self.assertTrue(any("edge_posture 'none'" in p for p in problems),
                        problems)


class TestRecordLineInternals(unittest.TestCase):
    def test_contains_words_edges(self):
        self.assertFalse(sh._contains_words([], ["a"]))
        self.assertFalse(sh._contains_words(["a"], ["a", "b"]))
        self.assertTrue(sh._contains_words(["a", "b"], ["b"]))

    def test_credited_name_colon_form(self):
        self.assertEqual(sh._credited_name("dependencies: Dependabot").strip(),
                         "Dependabot")

    def test_record_line_followed_by_overall_line(self):
        text = ("Scanners of record: dependabot, codeql, secret-scanning.\n"
                "Overall grade: A\n")
        scanning = {"dependencies": "dependabot", "sast": "codeql",
                    "secrets": "secret-scanning"}
        self.assertEqual(sh._record_line_problems(text, scanning), [])

    def test_unrecorded_kind_is_skipped(self):
        text = "Scanners of record: dependabot.\n"
        self.assertEqual(sh._record_line_problems(text, {}), [])


class TestHeaderInternals(unittest.TestCase):
    def test_addressish_rejections(self):
        self.assertFalse(sh._addressish("COPIES TO boss@example.com"))
        self.assertFalse(sh._addressish("Notes: someone@example.com"))
        self.assertFalse(sh._addressish("the staging host"))
        self.assertFalse(sh._addressish(""))

    def test_header_not_found(self):
        problems = sh._header_problems(cfg(), "no header in this text\n")
        self.assertTrue(any("header not found" in p for p in problems))

    def test_header_with_only_a_cc_label_is_not_a_header(self):
        problems = sh._header_problems(cfg(), "Cc: pal@example.com\n")
        self.assertTrue(any("header not found" in p for p in problems))

    def test_header_from_mismatch(self):
        report = ("From: Someone Else <other@example.com> · "
                  "To: owner@example.com\n") + SCANNERS_LINE + fx.SAMPLE_REPORT
        problems = run(cfg(), findings(), report)
        self.assertTrue(any("header From set" in p for p in problems),
                        problems)


class TestLoadJsonErrors(unittest.TestCase):
    def test_yaml_extension_rejected(self):
        with self.assertRaises(sh.InputError):
            sh._load_json(tmp_file("{}", suffix=".yaml"))

    def test_missing_file(self):
        with self.assertRaises(sh.InputError):
            sh._load_json("/nonexistent/definitely-missing.json")

    def test_malformed_json(self):
        with self.assertRaises(sh.InputError):
            sh._load_json(tmp_file("{not json"))

    def test_top_level_array_rejected(self):
        with self.assertRaises(sh.InputError):
            sh._load_json(tmp_file("[1, 2, 3]"))


class TestCliBranches(unittest.TestCase):
    def test_no_args_and_help(self):
        code, out = call_main()
        self.assertEqual(code, 1)
        self.assertIn("Deterministic helpers", out)
        code, _out = call_main("--help")
        self.assertEqual(code, 0)

    def test_unknown_command(self):
        code, _out = call_main("frobnicate")
        self.assertEqual(code, 1)

    def test_headers_url_branch_with_mocked_fetch(self):
        with mock.patch.object(sh, "fetch_headers",
                               return_value={
                                   "Content-Security-Policy":
                                       "default-src 'self'"}):
            code, out = call_main("headers", "https://example.com")
        self.assertEqual(code, 0)
        self.assertIn('"csp": "enforcing"', out)

    def test_headers_file_branches(self):
        missing = os.path.join(tempfile.gettempdir(),
                               "definitely-missing-headers.txt")
        code, out = call_main("headers", "--file", missing)
        self.assertEqual(code, 1)
        self.assertIn("file not found", out)
        empty = tmp_file("no header lines here\n", suffix=".txt")
        code, out = call_main("headers", "--file", empty)
        self.assertEqual(code, 1)
        self.assertIn("no 'Name: value' header lines", out)
        good = tmp_file(
            "Content-Security-Policy: default-src 'self'\n"
            "Strict-Transport-Security: max-age=15552000\n"
            "\nBody: ignored\n", suffix=".txt")
        code, out = call_main("headers", "--file", good)
        self.assertEqual(code, 0)
        self.assertIn('"csp": "enforcing"', out)

    def test_burst_branches(self):
        good = tmp_file(json.dumps(fx.SCANNER_BURST_SEGMENTS))
        code, out = call_main("burst", good)
        self.assertEqual(code, 0)
        self.assertIn("concentrated-event", out)
        bad = tmp_file(json.dumps({"total_errors": 3}))
        code, out = call_main("burst", bad)
        self.assertEqual(code, 1)
        self.assertIn("missing the key", out)

    def test_validate_config_prints_warnings_and_errors(self):
        c = cfg()
        del c["code_host_instance"]
        warn_path = tmp_file(json.dumps(c))
        code, out = call_main("validate-config", warn_path)
        self.assertEqual(code, 0)
        self.assertIn("WARNING:", out)
        bad = cfg()
        bad["edge_provider"] = "bogus-edge"
        bad_path = tmp_file(json.dumps(bad))
        code, out = call_main("validate-config", bad_path)
        self.assertEqual(code, 1)
        self.assertIn("ERROR:", out)

    def test_validate_report_branches(self):
        report_path = tmp_file(header() + SCANNERS_LINE + fx.SAMPLE_REPORT,
                               suffix=".md")
        findings_path = tmp_file(json.dumps(findings()))
        code, out = call_main("validate-report", report_path)
        self.assertEqual(code, 0)
        self.assertIn("structure only", out)
        code, out = call_main("validate-report", report_path, findings_path)
        self.assertEqual(code, 0)
        self.assertIn("structure and grades agree", out)
        code, _out = call_main("validate-report", report_path, findings_path,
                               "extra", "args")
        self.assertEqual(code, 1)
        code, out = call_main("validate-report", "/nonexistent/r.md")
        self.assertEqual(code, 1)
        self.assertIn("file not found", out)
        bad_report = tmp_file("nothing here\n", suffix=".md")
        code, out = call_main("validate-report", bad_report, findings_path)
        self.assertEqual(code, 1)
        self.assertIn("PROBLEM:", out)

    def test_validate_email_arg_branches(self):
        code, _out = call_main("validate-email", "a.html", "b.json", "c")
        self.assertEqual(code, 1)
        code, _out = call_main("validate-email", "--kind", "correction")
        self.assertEqual(code, 1)
        code, out = call_main("validate-email", "/nonexistent/e.html")
        self.assertEqual(code, 1)
        self.assertIn("file not found", out)

    def test_check_run_prints_problems(self):
        sim_cfg = cfg()
        del sim_cfg["code_host_instance"]
        cfg_path = tmp_file(json.dumps(sim_cfg))
        findings_path = tmp_file(json.dumps(findings()))
        report_path = tmp_file("no apparatus at all\n", suffix=".md")
        code, out = call_main("check-run", cfg_path, findings_path,
                              report_path)
        self.assertEqual(code, 1)
        self.assertIn("WARNING:", out)
        self.assertIn("PROBLEM:", out)
        code, out = call_main("check-run", cfg_path, findings_path,
                              "/nonexistent/report.md")
        self.assertEqual(code, 1)
        self.assertIn("file not found", out)
        code, _out = call_main("check-run", cfg_path)
        self.assertEqual(code, 1)

    def test_unreadable_file_branches(self):
        d = tempfile.gettempdir()
        code, out = call_main("headers", "--file", d)
        self.assertEqual(code, 1)
        self.assertIn("cannot read", out)
        code, out = call_main("validate-report", d)
        self.assertEqual(code, 1)
        self.assertIn("cannot read", out)
        code, out = call_main("validate-email", d)
        self.assertEqual(code, 1)
        self.assertIn("cannot read", out)
        cfg_path = tmp_file(json.dumps(cfg()))
        findings_path = tmp_file(json.dumps(findings()))
        code, out = call_main("check-run", cfg_path, findings_path, d)
        self.assertEqual(code, 1)
        self.assertIn("cannot read", out)

    def test_kind_only_invocations(self):
        code, _out = call_main("validate-report", "--kind", "correction")
        self.assertEqual(code, 1)
        cfg_path = tmp_file(json.dumps(cfg()))
        code, _out = call_main("check-run", "--kind", "correction",
                               cfg_path, cfg_path)
        self.assertEqual(code, 1)

    def test_main_guard_via_runpy(self):
        findings_path = tmp_file(json.dumps(findings()))
        with mock.patch.object(sys, "argv",
                               ["site_health.py", "grade", findings_path]):
            with self.assertRaises(SystemExit) as cm:
                runpy.run_path(CLI_PATH, run_name="__main__")
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
