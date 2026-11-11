# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 30 regressions: the subject line's overall grade is
checked like every other occurrence; huge integers never crash
the loader or the grader; the remaining intake fields are
type-checked; a graded leg's section must state its grade, in
numbered headings too."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
import fixtures  # noqa: E402
from test_round4 import cfg, findings, header, SCANNERS_LINE, run  # noqa: E402
from fixtures import SAMPLE_REPORT  # noqa: E402

REPORT = header() + SCANNERS_LINE + SAMPLE_REPORT


def base():
    return copy.deepcopy(fixtures.HEALTHY_GITHUB_CLOUDFLARE)


class TestRound30(unittest.TestCase):
    def test_subject_grade_without_colon_is_checked(self):
        subject = "Subject: Example Co daily report — overall grade A\n"
        problems = sh.validate_report(subject + REPORT, findings())
        self.assertEqual(problems, [])
        f = base()
        f["security"]["critical_public_exploit_in_production"] = True
        bad = "Subject: Example Co daily report — overall grade A\n" + REPORT
        problems = sh.validate_run(cfg(), f, bad)[0]
        self.assertTrue(any("overall grade contradiction" in p
                            for p in problems))

    def test_huge_cert_days_is_a_clean_error(self):
        f = base()
        f["security"]["cert_days_left"] = -(10 ** 400)
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_config_field_types_are_checked(self):
        c = cfg()
        c["repositories"] = {"web": 1}
        c["side_hosts"] = "api.example.com"
        c["owners"] = "Pat"
        c["staging"] = 123
        c["hosting"] = ["aws"]
        c["schedule"] = 123
        c["sending_route"] = 123
        errors, _ = sh._validate_config(c)
        text = " ".join(errors)
        for field in ("repositories", "side_hosts", "owners", "staging",
                      "hosting", "schedule", "sending_route"):
            self.assertIn(field, text)

    def test_deleted_section_grade_lines_are_flagged(self):
        import re as _re
        stripped = _re.sub(r"(?mi)^(.*grade\s*:?\s+)[A-F]\b", r"\1",
                           REPORT)
        problems = run(cfg(), findings(), stripped)
        self.assertTrue(any("missing section grade line" in p
                            for p in problems))

    def test_numbered_section_heading_grade_is_checked(self):
        bad = REPORT + "\n## 1. TRAFFIC & CLOUDFLARE — grade F\n"
        problems = run(cfg(), findings(), bad)
        self.assertTrue(any("section grade contradiction" in p
                            for p in problems))


if __name__ == "__main__":
    unittest.main()
