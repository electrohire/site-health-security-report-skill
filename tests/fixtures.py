# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Scenario fixtures: simulated stacks and days, shared by the tests.

Each fixture is a findings dict in the shape site_health.compute_grades
consumes, representing one customer's stack on one day.
"""

HEALTHY_GITHUB_CLOUDFLARE = {
    "traffic": {"five_xx_share": 0.001, "four_04_share": 0.04,
                "outage_confirmed": False, "repeated_reliability_problems": False},
    "seo_aeo": {"aeo_score": 100, "seo_score": 92},
    "security": {"critical": 0, "high": 0, "medium": 12, "low": 3,
                 "critical_public_exploit_in_production": False,
                 "code_scanning_on": True, "secret_scanning_on": True,
                 "secret_alerts_open": 0, "csp": "enforcing",
                 "observatory_grade": "A", "ssl_grade": "A+",
                 "cert_days_left": 70, "dmarc": "reject",
                 "privacy_failures": 0, "ci_blocked": False},
}

BITBUCKET_AWS_NO_SCANNING = {
    "traffic": {"five_xx_share": 0.003, "four_04_share": 0.06,
                "outage_confirmed": False, "repeated_reliability_problems": False},
    "seo_aeo": {"aeo_score": 88, "seo_score": 84},
    "security": {"critical": 0, "high": 0, "medium": 30, "low": 9,
                 "critical_public_exploit_in_production": False,
                 "code_scanning_on": False, "secret_scanning_on": False,
                 "secret_alerts_open": 0, "csp": "report-only",
                 "observatory_grade": "B", "ssl_grade": "A",
                 "cert_days_left": 45, "dmarc": "quarantine",
                 "privacy_failures": 0, "ci_blocked": False},
}

# The 2026-11-10 ElectroHire case, generalized: a huge 5xx burst that is
# one scanner address against a side host. IMPORTANT: a findings file
# always carries POST-segmentation traffic figures. The raw zone totals
# (5xx at 15.9% of traffic) live in SCANNER_BURST_SEGMENTS below; once the
# burst rule attributes them to the scanner, the day's residual server
# error share is small, and what remains is a noticeable 404 problem.
SCANNER_BURST_DAY = {
    "traffic": {"five_xx_share": 0.004, "four_04_share": 0.139,
                "outage_confirmed": False, "repeated_reliability_problems": False},
    "seo_aeo": {"aeo_score": 100, "seo_score": 88},
    "security": {"critical": 0, "high": 0, "medium": 86, "low": 11,
                 "critical_public_exploit_in_production": False,
                 "code_scanning_on": False, "secret_scanning_on": False,
                 "secret_alerts_open": 0, "csp": "report-only",
                 "observatory_grade": "B", "ssl_grade": "A+",
                 "cert_days_left": 74, "dmarc": "reject",
                 "privacy_failures": 0, "ci_blocked": True},
}
SCANNER_BURST_SEGMENTS = {"total_errors": 4391, "top_single_ip_errors": 4100,
                          "primary_host_errors": 120, "top_single_host_errors": 4200}

REAL_OUTAGE_SEGMENTS = {"total_errors": 4391, "top_single_ip_errors": 210,
                        "primary_host_errors": 3900, "top_single_host_errors": 3900}

DISTRIBUTED_FAILURE_SEGMENTS = {"total_errors": 10000, "top_single_ip_errors": 50,
                                "primary_host_errors": 4000, "top_single_host_errors": 4000}

EXPLOIT_IN_PRODUCTION = {
    "traffic": {"five_xx_share": 0.001, "four_04_share": 0.02,
                "outage_confirmed": False, "repeated_reliability_problems": False},
    "seo_aeo": {"aeo_score": 95, "seo_score": 90},
    "security": {"critical": 1, "high": 2, "medium": 5, "low": 1,
                 "critical_public_exploit_in_production": True,
                 "code_scanning_on": True, "secret_scanning_on": True,
                 "secret_alerts_open": 0, "csp": "enforcing",
                 "observatory_grade": "A", "ssl_grade": "A+",
                 "cert_days_left": 60, "dmarc": "reject",
                 "privacy_failures": 0, "ci_blocked": False},
}

BASE_CONFIG = {
    "site_name": "Example Co", "primary_host": "example.com",
    "side_hosts": [{"host": "api.example.com", "role": "api"}],
    "edge_provider": "cloudflare", "code_host": "github",
    "edge_credential": "location only: vault entry 'example-co/cf-analytics'",
    "hosting": "aws", "staging": {"url": "https://staging.example.com", "branch": "staging"},
    "standing_items": [],
    "sender": "Example Co Reports <reports@send.example.com>",
    "repositories": ["example/web"],
    "scanning": {"dependencies": "dependabot", "sast": "codeql",
                 "secrets": "secret-scanning"},
    "recipients": {"to": ["owner@example.com"], "cc": []},
    "owners": {"edge": "Pat", "code": "Sam", "content": "Jo", "business": "Owner"},
    "sending_route": "resend", "schedule": "daily 08:30",
    "timezone": "America/Detroit",
    "brand": {"display_name": "Example Co", "accent_color": "#000000"},
}

SAMPLE_REPORT = """Example Co daily report
OVERALL GRADE: A
Sub-grades: Traffic & reliability A · SEO/AEO A · Security & code health A
TRAFFIC & CLOUDFLARE — grade A
SEO / AEO — grade A
SECURITY & GITHUB — grade A
WEBSITE SECURITY SCANS
PRIVACY & COMPLIANCE
RECOMMENDATIONS (ranked)
"""
