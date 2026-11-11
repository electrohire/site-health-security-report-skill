# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 21 regressions: platform vulnerabilities count into the
Security grade, and an unverified site backup is a named cap."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
import fixtures  # noqa: E402


def base():
    return copy.deepcopy(fixtures.HEALTHY_GITHUB_CLOUDFLARE)


class TestRound21(unittest.TestCase):
    def test_platform_critical_counts(self):
        f = base()
        f["security"]["platform"] = {
            "source": "host security notice", "critical": 1, "high": 0}
        self.assertEqual(sh.compute_grades(f)["security"], "D")

    def test_platform_shape_is_validated(self):
        f = base()
        f["security"]["platform"] = {"critical": 1, "high": 0}
        with self.assertRaises(sh.InputError):
            sh.compute_grades(f)

    def test_unverified_backup_caps_at_c(self):
        f = base()
        f["security"]["site_backups_verified"] = False
        self.assertEqual(sh.compute_grades(f)["security"], "C")


if __name__ == "__main__":
    unittest.main()
