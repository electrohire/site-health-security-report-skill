# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 12 regressions: SKILL.md frontmatter for spec-conformant
discovery, the dependencies 'none' contradiction, address shape
validation, and the rubric boundary wording."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class TestRound12(unittest.TestCase):
    def test_skill_md_opens_with_matching_frontmatter(self):
        text = open(os.path.join(
            ROOT, "skills", "site-health-security-report",
            "SKILL.md")).read()
        self.assertTrue(text.startswith("---\n"))
        head = text.split("\n---\n", 1)[0]
        self.assertIn("name: site-health-security-report", head)
        self.assertIn("description:", head)

    def test_dependencies_none_with_counts_is_a_contradiction(self):
        c = cfg()
        c["scanning"]["dependencies"] = "none"
        problems = run(c, findings(), header() + SAMPLE_REPORT)
        self.assertTrue(any("dependencies" in p and "'none'" in p
                            for p in problems), problems)

    def test_malformed_recipient_and_sender_are_config_errors(self):
        c = cfg()
        c["recipients"]["to"] = ["owneratexample.com"]
        errors = sh.validate_config(c)
        self.assertTrue(any("no email address" in e for e in errors),
                        errors)
        c2 = cfg()
        c2["sender"] = "Reports (no address at all)"
        errors2 = sh.validate_config(c2)
        self.assertTrue(any("sender" in e for e in errors2), errors2)

    def test_observatory_d_plus_caps(self):
        f = findings()
        f["security"]["observatory_grade"] = "D+"
        self.assertEqual(sh.compute_grades(f)["security"], "C")
        f["security"]["observatory_grade"] = "C-"
        self.assertEqual(sh.compute_grades(f)["security"], "A")

    def test_share_boundaries_match_the_docs(self):
        f = findings()
        f["traffic"]["four_04_share"] = 0.10  # exactly 10%: still B
        f["traffic"]["five_xx_share"] = 0.001
        self.assertEqual(sh.compute_grades(f)["traffic"], "B")
        f2 = findings()
        f2["traffic"]["five_xx_share"] = 0.005  # exactly 0.5%: still B
        f2["traffic"]["four_04_share"] = 0.02
        self.assertEqual(sh.compute_grades(f2)["traffic"], "B")

    def test_readme_counts_twelve_questions(self):
        readme = open(os.path.join(ROOT, "README.md")).read()
        self.assertIn("twelve questions", readme)


if __name__ == "__main__":
    unittest.main()
