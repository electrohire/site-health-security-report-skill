# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ElectroHire Inc.
"""Round 27 regression: a report file saved with a UTF-8 BOM by a
consumer editor validates exactly like the same report without
one (the CLI reads report text as utf-8-sig)."""

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


class TestRound27(unittest.TestCase):
    def test_bom_text_validates_like_plain_text(self):
        # The parser-level invariant the CLI encoding relies on:
        # utf-8-sig decoding removes the BOM, so validate_run sees
        # the identical string.
        bom_text = ("﻿" + REPORT).encode("utf-8").decode("utf-8-sig")
        self.assertEqual(bom_text, REPORT)
        self.assertEqual(sh.validate_run(cfg(), findings(), bom_text),
                         ([], []))

    def test_cli_source_reads_reports_as_utf8_sig(self):
        src = open(os.path.join(os.path.dirname(__file__), "..", "skills",
                                "site-health-security-report", "scripts",
                                "site_health.py")).read()
        self.assertGreaterEqual(src.count('encoding="utf-8-sig"'), 2)


if __name__ == "__main__":
    unittest.main()
