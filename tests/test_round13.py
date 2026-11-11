# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 13 regressions: a scanner assertion for a config-'none' kind
is a contradiction at both layers (findings scanners_used and the
printed record line), and the certificate boundary is under 14 days."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402
from test_round4 import cfg, findings, header, run  # noqa: E402


class TestRound13(unittest.TestCase):
    def test_none_kind_named_in_scanners_used_is_flagged(self):
        c = cfg()
        c["scanning"]["dependencies"] = "none"
        f = findings()
        for k in ("critical", "high", "medium", "low", "total_open"):
            f["security"][k] = None
        problems = run(c, f, header() + SAMPLE_REPORT)
        self.assertTrue(any("scanners_used names" in p for p in problems),
                        problems)

    def test_none_kind_credited_on_the_record_line_is_flagged(self):
        c = cfg()
        c["scanning"]["dependencies"] = "none"
        f = findings()
        for k in ("critical", "high", "medium", "low", "total_open"):
            f["security"][k] = None
        del f["security"]["scanners_used"]["dependencies"]
        line = ("Scanners of record: dependency scanning by Dependabot, "
                "code scanning by CodeQL, secret scanning by GitHub "
                "Secret Scanning.\n")
        problems = run(c, f, header() + line + SAMPLE_REPORT)
        self.assertTrue(any("credits a dependencies scanner" in p
                            for p in problems), problems)

    def test_cert_boundary_is_under_14_days(self):
        f = findings()
        f["security"]["cert_days_left"] = 14
        self.assertEqual(sh.compute_grades(f)["security"], "A")
        f["security"]["cert_days_left"] = 13
        self.assertEqual(sh.compute_grades(f)["security"], "C")


if __name__ == "__main__":
    unittest.main()
