# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 17 regressions: the stack-selection page carries the prices
it claims to carry, and the template's null-score clause matches the
grader (the leg grades from the remaining score)."""

import os
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
SKILL = os.path.join(ROOT, "skills", "site-health-security-report")


class TestRound17(unittest.TestCase):
    def test_stack_selection_carries_prices(self):
        page = open(os.path.join(ROOT, "docs", "stack-selection.md")).read()
        for figure in ("$20", "$49", "$2,944", "$3,000"):
            self.assertIn(figure, page)

    def test_template_null_score_clause_matches_the_grader(self):
        tpl = open(os.path.join(
            SKILL, "templates", "report-template.md")).read()
        self.assertNotIn("and grade the leg not available", tpl)
        self.assertIn("it is not available only when both scores "
                      "are null", tpl)


if __name__ == "__main__":
    unittest.main()
