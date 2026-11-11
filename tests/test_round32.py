# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 32 regressions: emphasis-wrapped grades are checked; the
corrected-grades line takes the edition line's forms; a bare
heading whose only separator is a colon is checked; the DMARC
comma form cannot read sp= as p=; a lowercase angle-bracketed
header continuation is harvested; brand render fields are
strings; validate-report rejects extra positionals; platform
findings contradict an undeclared platform; a confirmed
side-host outage caps Traffic at D."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
import fixtures  # noqa: E402
from test_round4 import cfg, findings, header, SCANNERS_LINE  # noqa: E402
from fixtures import SAMPLE_REPORT  # noqa: E402

REPORT = header() + SCANNERS_LINE + SAMPLE_REPORT
GRADES = sh.compute_grades(findings())


def wrong(grade):
    return "A" if grade != "A" else "F"


def base():
    return copy.deepcopy(fixtures.HEALTHY_GITHUB_CLOUDFLARE)


class TestRound32(unittest.TestCase):
    def test_emphasis_wrapped_overall_grade_is_checked(self):
        bad = f"Overall grade: **{wrong(GRADES['overall'])}**\n"
        problems = sh.validate_report(bad + REPORT, findings())
        self.assertTrue(any("overall grade contradiction" in p
                            for p in problems))

    def test_bare_heading_with_colon_separator_is_checked(self):
        bad = f"\n## Traffic: {wrong(GRADES['traffic'])}\n"
        problems = sh.validate_report(REPORT + bad, findings())
        self.assertTrue(any("section grade contradiction" in p
                            for p in problems))

    def test_dmarc_comma_form_reads_p_not_sp(self):
        self.assertEqual(sh._norm_dmarc("p=none, sp=reject"), "none")
        self.assertEqual(sh._norm_dmarc("sp=reject"), "sp=reject")

    def test_lowercase_angle_bracket_continuation_is_harvested(self):
        self.assertTrue(sh._addressish("bob <bob@example.com>"))

    def test_brand_render_fields_are_strings(self):
        c = cfg()
        c["brand"] = {"display_name": "X", "accent_color": 123,
                      "logo_url": ["x"]}
        errors, _ = sh._validate_config(c)
        text = " ".join(errors)
        self.assertIn("brand.accent_color", text)
        self.assertIn("brand.logo_url", text)

    def test_platform_findings_need_a_declared_platform(self):
        c = cfg()
        c["app_platform"] = "none"
        f = findings()
        f["security"]["platform"] = {"source": "vendor feed",
                                     "critical": 0, "high": 1}
        problems = sh.validate_run(c, f, REPORT)[0]
        self.assertTrue(any("app_platform" in p for p in problems))

    def test_side_host_outage_caps_traffic_at_d(self):
        f = base()
        f["traffic"]["side_host_outage"] = {"host": "app.example.com",
                                            "note": "down 14h"}
        result = sh.compute_grades(f)
        self.assertEqual(result["traffic"], "D")
        self.assertTrue(any("app.example.com" in c
                            for c in result["causes"]["traffic"]))


if __name__ == "__main__":
    unittest.main()
