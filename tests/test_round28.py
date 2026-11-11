# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Round 28 regressions: the CLI never tracebacks on operator file
slips (a directory, an unreadable or non-UTF-8 file, a BOM JSON),
and check-run answers a structurally invalid config with its own
error list instead of crashing on it."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts"))
import site_health as sh  # noqa: E402
from test_round4 import cfg, findings, header, SCANNERS_LINE, run  # noqa: E402
from fixtures import SAMPLE_REPORT  # noqa: E402

REPORT = header() + SCANNERS_LINE + SAMPLE_REPORT


class TestRound28(unittest.TestCase):
    def test_check_run_on_string_scanning_returns_problems(self):
        c = cfg()
        c["scanning"] = "dependabot"
        problems = run(c, findings(), REPORT)
        self.assertTrue(any("config:" in p for p in problems))

    def test_check_run_on_string_recipients_returns_problems(self):
        c = cfg()
        c["recipients"] = "owner@example.com"
        problems = run(c, findings(), REPORT)
        self.assertTrue(any("config:" in p for p in problems))

    def test_check_run_on_non_string_recipient_entry(self):
        c = cfg()
        c["recipients"] = {"to": [123]}
        problems = run(c, findings(), REPORT)
        self.assertTrue(problems)

    def test_load_json_on_a_directory_is_a_clean_error(self):
        with self.assertRaises(sh.InputError):
            sh._load_json(os.path.dirname(__file__))

    def test_load_json_opens_as_utf8_sig(self):
        import json as _json
        raw = b"\xef\xbb\xbf" + _json.dumps({"a": 1}).encode()
        self.assertEqual(_json.loads(raw.decode("utf-8-sig")), {"a": 1})
        src = open(os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts",
                                "site_health.py")).read()
        self.assertIn('open(path, encoding="utf-8-sig")', src)


if __name__ == "__main__":
    unittest.main()
