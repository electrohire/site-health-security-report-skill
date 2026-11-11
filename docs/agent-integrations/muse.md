<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Meta Muse

Muse loads skills from its skills directories; place `skills/site-health-security-report/` in `~/workspace/custom-skills/site-health-security-report/` for a personal install, or keep it in the project workspace for a project install. Invoke it by describing the outcome ("Produce the daily site health report for the configured site") and Muse routes to the skill. Muse's scheduled jobs are the natural scheduler: a daily task whose body is the skill invocation plus the saved config path, with delivery to the chat of record.
