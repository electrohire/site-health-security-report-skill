# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 16 regressions: the 'none'-kind credit test knows the full
recognized scanner vocabulary (including the commercial tools), and
code_host_ci is a known config key."""

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


class TestRound16(unittest.TestCase):
    def test_commercial_scanner_credits_flag_for_none_kind(self):
        for segment in ("dependency scanning by Snyk",
                        "dependency scanning by Trivy"):
            problems = _problems(segment)
            self.assertTrue(any("credits a dependencies" in p
                                for p in problems), (segment, problems))

    def test_code_host_ci_is_a_known_key(self):
        c = cfg()
        c["code_host_ci"] = "woodpecker"
        self.assertEqual(sh.validate_config(c), [])
        warnings = sh.validate_config_warnings(c)
        self.assertFalse(any("code_host_ci" in w for w in warnings),
                         warnings)


if __name__ == "__main__":
    unittest.main()
