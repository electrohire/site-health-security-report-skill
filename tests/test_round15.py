# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 15 regressions: the 'none'-kind record-line check credits
only actual scanner names — bare role phrases, negated mentions, and
parenthetical remarks are not credits; real credits still flag."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run  # noqa: E402


def _problems(segment):
    c = cfg()
    c["scanning"]["dependencies"] = "none"
    f = findings()
    for k in ("critical", "high", "medium", "low", "total_open"):
        f["security"][k] = None
    del f["security"]["scanners_used"]["dependencies"]
    line = ("Scanners of record: " + segment + "; code scanning by "
            "CodeQL; secret scanning by GitHub Secret Scanning.\n")
    return run(c, f, header() + line + SAMPLE_REPORT)


class TestRound15(unittest.TestCase):
    def test_role_phrase_alone_is_not_a_credit(self):
        problems = _problems("dependency scanning")
        self.assertFalse(any("credits a dependencies" in p
                             for p in problems), problems)

    def test_not_run_is_not_a_credit(self):
        problems = _problems("dependency scanning not run")
        self.assertFalse(any("credits a dependencies" in p
                             for p in problems), problems)

    def test_negated_credit_is_not_a_credit(self):
        problems = _problems(
            "dependency scanning by Dependabot was not used")
        self.assertFalse(any("credits a dependencies" in p
                             for p in problems), problems)

    def test_parenthetical_remark_is_not_a_credit(self):
        problems = _problems("dependency scanning (paused this week)")
        self.assertFalse(any("credits a dependencies" in p
                             for p in problems), problems)
        problems = _problems("dependency scanning (none this week)")
        self.assertFalse(any("credits a dependencies" in p
                             for p in problems), problems)

    def test_real_credits_still_flag(self):
        for segment in ("dependency scanning by Dependabot",
                        "dependency scanning (Dependabot)",
                        "dependency scanning — Dependabot"):
            problems = _problems(segment)
            self.assertTrue(any("credits a dependencies" in p
                                for p in problems), (segment, problems))


if __name__ == "__main__":
    unittest.main()
