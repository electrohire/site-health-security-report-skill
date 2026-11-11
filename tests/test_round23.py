# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 23 regressions: a confirmed compromise is a Security F,
and an outage carries its recorded cause."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
import fixtures  # noqa: E402
from test_round4 import cfg, findings, header, run  # noqa: E402
from test_round3 import SAMPLE_REPORT  # noqa: E402


def base():
    return copy.deepcopy(fixtures.HEALTHY_GITHUB_CLOUDFLARE)


class TestRound23(unittest.TestCase):
    def test_compromise_is_security_f(self):
        f = base()
        f["security"]["compromise_confirmed"] = True
        result = sh.compute_grades(f)
        self.assertEqual(result["security"], "F")
        self.assertTrue(any("compromise" in c
                            for c in result["causes"]["security"]))

    def test_outage_note_is_carried_into_the_cause(self):
        f = findings()
        f["traffic"]["outage_confirmed"] = True
        f["traffic"]["outage_note"] = "host suspended the account"
        f["traffic"]["burst"] = {
            "total_errors": 100, "top_single_ip_errors": 7,
            "primary_host_errors": 90, "top_single_host_errors": 90}
        result = sh.compute_grades(f)
        self.assertEqual(result["traffic"], "F")
        self.assertTrue(any("host suspended" in c
                            for c in result["causes"]["traffic"]))


if __name__ == "__main__":
    unittest.main()
