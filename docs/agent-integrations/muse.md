<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 ElectroHire Inc.
-->
# Meta Muse

Muse loads skills from its skills directories; place `skills/site-health-security-report/` in `~/workspace/custom-skills/site-health-security-report/` for a personal install, or keep it in the project workspace for a project install. Verify the load before intake: ask Muse to state the skill's rule zero (the mandatory stack intake); if it cannot, the skill is not loaded. Invoke it by describing the outcome ("Produce the daily site health report for the configured site") and Muse routes to the skill. Muse's scheduled jobs are the natural scheduler: a task at the config's cadence whose body is the skill invocation plus the saved config path (the config carries the timezone and the recipients; the job sends nothing the config does not authorize), with delivery to the chat of record.
