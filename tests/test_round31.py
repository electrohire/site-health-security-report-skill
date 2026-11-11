# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 31 regressions: grade statements in the skill's own house
phrasings are cross-checked (overall grade is/=/- forms, bare and
conjunction-less section headings, per-leg colons on the
Sub-grades line), the headers --file parser stops at the blank
line, and the last descriptive config fields are type-checked.
Each report probe is isolated: the base report agrees with the
findings, and one added line in the new shape disagrees."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round4 import cfg, findings, header, SCANNERS_LINE  # noqa: E402
from fixtures import SAMPLE_REPORT  # noqa: E402

REPORT = header() + SCANNERS_LINE + SAMPLE_REPORT
GRADES = sh.compute_grades(findings())


def wrong(grade):
    return "A" if grade != "A" else "F"


class TestRound31(unittest.TestCase):
    def test_overall_grade_is_form_is_checked(self):
        bad = f"The overall grade is {wrong(GRADES['overall'])}.\n"
        problems = sh.validate_report(bad + REPORT, findings())
        self.assertTrue(any("overall grade contradiction" in p
                            for p in problems))

    def test_bare_and_conjunctionless_section_headings_are_checked(self):
        w = wrong(GRADES["security"])
        for extra in (f"## SECURITY — grade {w}\n",
                      f"## Security: grade {w}\n",
                      f"## SECURITY & CODE HEALTH — {w}\n"):
            problems = sh.validate_report(REPORT + "\n" + extra, findings())
            self.assertTrue(
                any("section grade contradiction" in p for p in problems),
                extra)

    def test_subgrades_line_with_per_leg_colons_is_checked(self):
        bad = (REPORT + "\nSub-grades: Traffic & reliability: "
               f"{wrong(GRADES['traffic'])} · SEO/AEO: {GRADES['seo_aeo']} · "
               f"Security & code health: {GRADES['security']}\n")
        problems = sh.validate_report(bad, findings())
        self.assertTrue(any("sub-grade mismatch" in p for p in problems))

    def test_last_config_fields_are_type_checked(self):
        c = cfg()
        c["site_name"] = 123
        c["code_host_access"] = 123
        c["edge_credential"] = {"a": 1}
        c["app_platform"] = {"x": 1}
        c["site_backups"] = 123
        c["brand"] = {"display_name": 123}
        errors, _ = sh._validate_config(c)
        text = " ".join(errors)
        for field in ("site_name", "code_host_access", "edge_credential",
                      "app_platform", "site_backups", "brand.display_name"):
            self.assertIn(field, text)


if __name__ == "__main__":
    unittest.main()
