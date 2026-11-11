#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 ElectroHire Inc.
"""Deterministic helpers for the Site Health & Security Report skill.

Standard library only. These functions make the report's judgment calls
mechanical: header posture, error-burst classification (outage vs
scanner event), A-F grading from a findings file, config validation
(the stack intake), and report validation.

Inputs are validated strictly. A findings or config value of the wrong
type or outside its range is an error, never a grade: a string "false"
must not manufacture an outage, and a missing measurement must not
manufacture an A. (Red-team findings, rounds 1-3.)

CLI:
  site_health.py headers https://example.com
  site_health.py grade findings.json
  site_health.py burst burst.json
  site_health.py validate-config config.json     (JSON is the config of record)
  site_health.py validate-report report.md findings.json [--kind correction]
  site_health.py check-run config.json findings.json report.md [--kind correction]
check-run is the validation of record for an edition: it validates the
config, the findings, and the report together, including that the
findings do not contradict the config and that the report's recipients
and sender match the config.
Exit code 0 means "ran and passed"; 1 means problems were printed.
All error paths print a clean ERROR line, never a traceback.
"""
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo

GRADE_ORDER = ["F", "D", "C", "B", "A"]  # worst to best

# The vendors' real grade scales. Observatory (MDN) issues plus/minus
# grades; SSL Labs issues E as well as T (trust ignored) and M (name
# mismatch). Ranks make "below B" mechanical on the real scales.
OBSERVATORY_GRADES = {"A+": 12, "A": 11, "A-": 10, "B+": 9, "B": 8, "B-": 7,
                      "C+": 6, "C": 5, "C-": 4, "D+": 3, "D": 2, "D-": 1, "F": 0}
SSL_GRADES = {"A+": 8, "A": 7, "A-": 6, "B": 5, "C": 4, "D": 3, "E": 2,
              "F": 1, "T": 0, "M": 0}


class InputError(ValueError):
    pass


def _is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _req_bool(section, key, where):
    v = section.get(key)
    if not isinstance(v, bool):
        raise InputError(f"{where}.{key} must be a JSON boolean, got {v!r}")
    return v


def _req_share(section, key, where):
    v = section.get(key)
    if not _is_number(v) or not 0.0 <= v <= 1.0:
        raise InputError(f"{where}.{key} must be a number between 0 and 1, got {v!r}")
    return float(v)


def _req_count(section, key, where):
    v = section.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise InputError(f"{where}.{key} must be a non-negative integer, got {v!r}")
    return v


def _opt_score(section, key, where):
    v = section.get(key)
    if v is None:
        return None
    if not _is_number(v) or not 0 <= v <= 100:
        raise InputError(f"{where}.{key} must be a number between 0 and 100 or null, got {v!r}")
    return v


def _norm(value, upper=False):
    if value is None:
        return None
    s = str(value).strip()
    return s.upper() if upper else s.lower()


def _norm_csp(value):
    s = _norm(value)
    if s is None:
        return None
    s = s.replace("_", "-")
    if s in ("enforcing", "report-only", "missing"):
        return s
    if s in ("none", "absent", "no"):
        return "missing"
    return s


def _norm_dmarc(value):
    """Accept the enum, or a raw DMARC policy/record an agent transcribed.

    A raw record is parsed by its tags: the policy is the value of the
    `p=` tag specifically. Substring matching misreads real records
    (`sp=reject` is the subdomain policy, and `p=` can appear inside a
    reporting address), grading a p=none domain as reject.
    """
    s = _norm(value)
    if s is None:
        return None
    if s in ("reject", "quarantine", "none", "missing"):
        return s
    if ";" in s or s.startswith("v=dmarc"):
        policies = set()
        for part in s.split(";"):
            m = re.match(r"p\s*=\s*(reject|quarantine|none)\b", part.strip())
            if m:
                policies.add(m.group(1))
        if len(policies) == 1:
            return policies.pop()
        return s  # no p= tag, or conflicting duplicates: not a valid record
    if "p=reject" in s:
        return "reject"
    if "p=quarantine" in s:
        return "quarantine"
    if "p=none" in s:
        return "none"
    return s


def _cap(current, ceiling):
    return GRADE_ORDER[min(GRADE_ORDER.index(current), GRADE_ORDER.index(ceiling))]


def _band_from_score(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"


# ---------------------------------------------------------------- headers

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def check_headers(headers):
    """headers: dict of response headers (any key case).

    Values are inspected, not just names: an empty value counts as
    missing, and Strict-Transport-Security with max-age=0 counts as
    disabled, not present. An enforcing Content-Security-Policy counts;
    a Content-Security-Policy-Report-Only header does not.
    """
    lower = {}
    notes = []
    for k, v in headers.items():
        if not isinstance(v, str):
            notes.append(f"header {k!r} had a non-string value and was ignored")
            continue
        val = v.strip()
        if val:
            lower[str(k).lower()] = val
    if "strict-transport-security" in lower:
        m = re.search(r"max-age\s*=\s*(\d+)", lower["strict-transport-security"])
        if not m:
            del lower["strict-transport-security"]
            notes.append("Strict-Transport-Security present but carries no max-age; counted as missing")
        elif int(m.group(1)) == 0:
            del lower["strict-transport-security"]
            notes.append("Strict-Transport-Security present but max-age=0 (disabled); counted as missing")
    present = [h for h in SECURITY_HEADERS if h in lower]
    missing = [h for h in SECURITY_HEADERS if h not in lower]
    if "content-security-policy" in lower:
        csp = "enforcing"
    elif "content-security-policy-report-only" in lower:
        csp = "report-only"
    else:
        csp = "missing"
    return {"present": present, "missing": missing, "csp": csp,
            "count": len(present), "of": len(SECURITY_HEADERS), "notes": notes}


def fetch_headers(url):
    if not re.match(r"^https?://", url or ""):
        raise InputError(f"not an http(s) URL: {url!r}")
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "site-health-report/1.0"})
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
            return dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        return dict(e.headers.items())
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError) as e:
        raise InputError(f"could not fetch headers from {url}: {e}")


# ---------------------------------------------------------------- bursts

def classify_error_burst(total_errors, top_single_ip_errors, primary_host_errors,
                         top_single_host_errors=None):
    """Decide whether a 5xx burst is an outage or a concentrated event.

    Returns "outage", "concentrated-event", or "distributed".
    - concentrated-event: one client address accounts for 60% or more
      of the errors, or one (side) host accounts for 60% or more while
      the primary host accounts for under half.
    - outage: the primary host accounts for at least half and no single
      address dominates.
    - distributed: errors spread across hosts roughly in proportion to
      their traffic (an origin, network, or region failure pattern).
      Grade on volume, investigate; it is not a scanner event and not
      automatically a site outage.
    top_single_host_errors should always be recorded; without it, a
    sub-50% primary share can only be called "distributed".
    """
    for name, v in (("total_errors", total_errors),
                    ("top_single_ip_errors", top_single_ip_errors),
                    ("primary_host_errors", primary_host_errors),
                    ("top_single_host_errors", top_single_host_errors)):
        if v is None and name == "top_single_host_errors":
            continue
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise InputError(f"{name} must be a non-negative integer, got {v!r}")
        if name != "total_errors" and v > total_errors:
            raise InputError(f"{name} ({v}) cannot exceed total_errors ({total_errors})")
    if top_single_host_errors is not None and top_single_host_errors < primary_host_errors:
        raise InputError(f"top_single_host_errors ({top_single_host_errors}) cannot be "
                         f"less than primary_host_errors ({primary_host_errors}): the "
                         f"busiest host has at least the primary host's errors. The two "
                         f"fields look swapped; a swap is exactly how a concentrated "
                         f"event gets misread as an outage")
    if total_errors <= 0:
        return "distributed"
    # Integer-exact threshold comparisons (no float rounding at the line).
    if top_single_ip_errors * 5 >= total_errors * 3:      # >= 60%
        return "concentrated-event"
    if primary_host_errors * 2 >= total_errors:           # >= 50%
        return "outage"
    if top_single_host_errors is not None and top_single_host_errors * 5 >= total_errors * 3:
        return "concentrated-event"
    return "distributed"


def _burst_from_findings(traffic, outage_claim=False):
    """Validate the optional traffic.burst segmentation record.

    Returns the classification when a record is present, else None. The
    record is what makes an outage claim mechanical instead of asserted.
    An outage claim needs the full record, top single host included:
    without it, a side-host event cannot be told from an outage.
    """
    burst = traffic.get("burst")
    if burst is None:
        return None
    if not isinstance(burst, dict):
        raise InputError("traffic.burst must be an object with the segmentation counts")
    if outage_claim and burst.get("top_single_host_errors") is None:
        raise InputError("traffic.burst is missing top_single_host_errors: an outage "
                         "claim needs the full segmentation record (total, top single "
                         "IP, primary host, top single host)")
    try:
        return classify_error_burst(burst["total_errors"], burst["top_single_ip_errors"],
                                    burst["primary_host_errors"],
                                    burst.get("top_single_host_errors"))
    except KeyError as e:
        raise InputError(f"traffic.burst is missing the key {e}: an outage claim needs "
                         f"the full segmentation record (total, top single IP, primary "
                         f"host, top single host)")


# ---------------------------------------------------------------- grading

def _validate_findings(findings):
    if not isinstance(findings, dict):
        raise InputError("findings must be a JSON object")
    for section in ("traffic", "seo_aeo", "security"):
        if section in findings and not isinstance(findings[section], dict):
            raise InputError(f"findings.{section} must be an object")
    t = findings.get("traffic")
    if t is None:
        raise InputError("findings.traffic is missing: a leg that did not run is "
                         "reported as not available, never graded from nothing")
    _req_share(t, "five_xx_share", "traffic")
    _req_share(t, "four_04_share", "traffic")
    _req_bool(t, "outage_confirmed", "traffic")
    if "repeated_reliability_problems" in t:
        _req_bool(t, "repeated_reliability_problems", "traffic")
    s = findings.get("security")
    if s is None:
        raise InputError("findings.security is missing: a leg that did not run is "
                         "reported as not available, never graded from nothing")
    for key in ("critical", "high"):
        if s.get(key) is not None:
            _req_count(s, key, "security")
        elif key not in s:
            raise InputError(f"security.{key} is missing: record the count, or null "
                             f"when no scanner ran and the count is not measured "
                             f"(null grades the run incomplete, never clean)")
    _req_bool(s, "code_scanning_on", "security")
    _req_bool(s, "secret_scanning_on", "security")
    if _norm_csp(s.get("csp")) not in ("enforcing", "report-only", "missing"):
        raise InputError(f"security.csp must be 'enforcing', 'report-only', or 'missing' "
                         f"(measured, never omitted), got {s.get('csp')!r}")
    if _norm_dmarc(s.get("dmarc")) not in ("reject", "quarantine", "none", "missing"):
        raise InputError(f"security.dmarc must be 'reject', 'quarantine', 'none', or "
                         f"'missing' (or a raw DMARC record carrying its p= policy; "
                         f"measured, never omitted), got {s.get('dmarc')!r}")
    for key, valid in (("observatory_grade", OBSERVATORY_GRADES),
                       ("ssl_grade", SSL_GRADES)):
        v = s.get(key)
        if v is not None and _norm(v, upper=True) not in valid:
            raise InputError(f"security.{key} must be one of {sorted(valid)} or null, "
                             f"got {v!r} (a numeric score belongs in the evidence "
                             f"record, not here)")
    for key in ("medium", "low"):
        if key in s and s.get(key) is not None:
            _req_count(s, key, "security")
    if _norm(s.get("edge_posture")) not in ("protected", "cdn-only", "none"):
        raise InputError(f"security.edge_posture must be 'protected' (edge with WAF or "
                         f"equivalent application-layer protection verified), 'cdn-only' "
                         f"(edge present, no such protection verified), or 'none' (no edge "
                         f"in front of the origin), got {s.get('edge_posture')!r}")
    seo = findings.get("seo_aeo") or {}
    _opt_score(seo, "aeo_score", "seo_aeo")
    _opt_score(seo, "seo_score", "seo_aeo")


def grade_security(f):
    causes = []
    grade = "A"
    exploit = False
    if "critical_public_exploit_in_production" in f:
        exploit = _req_bool(f, "critical_public_exploit_in_production", "security")
    if exploit:
        grade = "F"
        causes.append("a critical alert with a public exploit affects production")
    if f.get("compromise_confirmed"):
        _req_bool(f, "compromise_confirmed", "security")
        grade = "F"
        causes.append("a compromise of the site was confirmed this period "
                      "(content, account, or platform integrity breached)")
    critical = f.get("critical")
    high = f.get("high")
    platform = f.get("platform")
    if platform is not None:
        if not isinstance(platform, dict):
            raise InputError("security.platform must be an object with "
                             "source, critical, high")
        for key in ("critical", "high"):
            value = platform.get(key)
            if not isinstance(value, int) or isinstance(value, bool) \
                    or value < 0:
                raise InputError(f"security.platform.{key} must be a "
                                 f"non-negative integer, got {value!r}")
        if not platform.get("source"):
            raise InputError("security.platform.source must name the "
                             "platform advisory source")
        if platform["critical"] > 0:
            grade = _cap(grade, "D")
            causes.append(f"{platform['critical']} critical platform "
                          f"vulnerabilit(ies) open ({platform['source']})")
        if platform["high"] > 0:
            grade = _cap(grade, "C")
            causes.append(f"{platform['high']} high platform "
                          f"vulnerabilit(ies) open ({platform['source']})")
    if critical is not None and critical > 0:
        grade = _cap(grade, "D")
        causes.append(f"{critical} critical dependency/code alert(s) open")
    if high is not None and high > 0:
        grade = _cap(grade, "C")
        causes.append(f"{high} high-severity alert(s) open")
    if critical is None or high is None:
        causes.append("dependency/code alert counts were not measured this run "
                      "(no scanner output to count); the run is incomplete")
    cert_days = f.get("cert_days_left")
    if cert_days is not None and (not _is_number(cert_days) or cert_days != cert_days
                                  or cert_days in (float("inf"), float("-inf"))):
        raise InputError(f"security.cert_days_left must be a finite number or null, "
                         f"got {cert_days!r}")
    cert_cause = None
    if cert_days is not None and cert_days < 0:
        cert_cause = f"the TLS certificate expired {-cert_days:g} day(s) ago"
    elif cert_days is not None and cert_days < 14:
        cert_cause = "TLS certificate expires within 14 days"
    privacy_failures = f.get("privacy_failures", 0)
    if not isinstance(privacy_failures, int) or isinstance(privacy_failures, bool) \
            or privacy_failures < 0:
        raise InputError(f"security.privacy_failures must be a non-negative integer, "
                         f"got {privacy_failures!r}")
    secret_alerts = f.get("secret_alerts_open", 0)
    if not isinstance(secret_alerts, int) or isinstance(secret_alerts, bool) or secret_alerts < 0:
        raise InputError(f"security.secret_alerts_open must be a non-negative integer, "
                         f"got {secret_alerts!r}")
    ci_blocked = f.get("ci_blocked", False)
    if not isinstance(ci_blocked, bool):
        raise InputError(f"security.ci_blocked must be a JSON boolean, got {ci_blocked!r}")
    backups = f.get("site_backups_verified")
    if backups is not None and not isinstance(backups, bool):
        raise InputError("security.site_backups_verified must be a JSON "
                         f"boolean, got {backups!r}")
    obs = _norm(f.get("observatory_grade"), upper=True)
    sslg = _norm(f.get("ssl_grade"), upper=True)
    named_caps = [
        (not f["code_scanning_on"], "code scanning is dark on at least one product repo"),
        (not f["secret_scanning_on"], "secret scanning is dark on at least one product repo"),
        (secret_alerts > 0, "secret-scanning alert(s) open"),
        (_norm_csp(f.get("csp")) == "report-only", "Content-Security-Policy is report-only, not enforcing"),
        (_norm_csp(f.get("csp")) == "missing", "no Content-Security-Policy header"),
        (_norm(f.get("edge_posture")) == "none", "no edge/DDoS layer in front of the origin"),
        (_norm(f.get("edge_posture")) == "cdn-only", "edge present but no WAF or application-layer protection verified in block mode"),
        (obs is not None and OBSERVATORY_GRADES.get(obs, 99) <= OBSERVATORY_GRADES["D+"],
         f"Mozilla Observatory grade {obs}"),
        (sslg is not None and SSL_GRADES.get(sslg, 99) < SSL_GRADES["B"],
         f"SSL Labs grade {sslg} is below B"),
        (cert_cause is not None, cert_cause),
        (_norm_dmarc(f.get("dmarc")) in ("none", "missing"), f"DMARC policy is {_norm_dmarc(f.get('dmarc'))}"),
        (privacy_failures > 0, f"{privacy_failures} privacy/AI spot check(s) failing"),
        (ci_blocked, "CI/CD cannot run, so the security pipeline cannot run either"),
        (backups is False, "no verified backup of the site itself"),
    ]
    for hit, text in named_caps:
        if hit:
            grade = _cap(grade, "C")
            causes.append(text)
    return grade, causes


def grade_seo_aeo(f):
    # A score without its run identifier is a number without provenance:
    # it could be yesterday's. The identifier ties it to this run's
    # checker record, which the pre-send gate re-reads.
    for score_key, id_key in (("aeo_score", "aeo_scan_id"), ("seo_score", "seo_scan_id")):
        if f.get(score_key) is not None:
            sid = f.get(id_key)
            if not isinstance(sid, str) or not sid.strip():
                raise InputError(f"seo_aeo.{id_key} is required when {score_key} is "
                                 f"present: record the checker run identifier for "
                                 f"this run (a score reused from a previous day has "
                                 f"no identifier for today and must be null instead)")
    scores = [s for s in (_opt_score(f, "aeo_score", "seo_aeo"),
                          _opt_score(f, "seo_score", "seo_aeo")) if s is not None]
    if not scores:
        return None, ["no SEO/AEO score could be produced this run; the leg is "
                      "reported as not available and the overall grade is incomplete"]
    grade = _band_from_score(min(scores))
    if grade == "A":
        return grade, []
    band = {"B": "the 80-89 band", "C": "the 70-79 band",
            "D": "the 50-69 band", "F": "below 50"}[grade]
    return grade, [f"the lowest SEO/AEO score is {min(scores):g}, in {band}"]


def grade_traffic(f):
    causes = []
    outage = _req_bool(f, "outage_confirmed", "traffic")
    classification = _burst_from_findings(f, outage_claim=outage)
    if outage and classification is None:
        raise InputError("traffic.outage_confirmed is true but no traffic.burst "
                         "segmentation record is present: an outage is established by "
                         "the burst record, never asserted. Add the segmentation "
                         "counts (total, top single IP, primary host, top single host) "
                         "to traffic.burst")
    if classification is not None and outage != (classification == "outage"):
        raise InputError(f"traffic.outage_confirmed is {str(outage).lower()} but the "
                         f"burst record classifies as '{classification}': the claim "
                         f"and the record disagree, and the record governs")
    if f.get("classification_pending") and classification is not None:
        _req_bool(f, "classification_pending", "traffic")
        raise InputError("traffic.classification_pending is true but a "
                         "traffic.burst record is present: the "
                         "classification has landed, so clear the flag "
                         "and grade on the record")
    if outage:
        causes = ["the primary host was confirmed down (burst record: primary host "
                  "carried at least half the errors, no single client dominating)"]
        note = f.get("outage_note")
        if note is not None:
            if not isinstance(note, str) or not note.strip():
                raise InputError("traffic.outage_note must be a non-empty "
                                 "string when present")
            causes.append(f"recorded cause: {note}")
        if f.get("repeated_reliability_problems"):
            _req_bool(f, "repeated_reliability_problems", "traffic")
            causes.append("reliability problems repeated across days")
        return "F", causes
    if f.get("classification_pending"):
        _req_bool(f, "classification_pending", "traffic")
        if classification is not None:
            raise InputError("traffic.classification_pending is true but a "
                             "traffic.burst record is present: the "
                             "classification has landed, so clear the flag "
                             "and grade on the record")
        return None, ["an error spike's classification was still pending "
                      "at send time; the traffic leg is not graded on an "
                      "unsegmented share"]
    share = _req_share(f, "five_xx_share", "traffic")
    share404 = _req_share(f, "four_04_share", "traffic")
    grade = "A"
    if share > 0.02:
        grade = "D"
        causes.append(f"server errors were {share:.1%} of traffic")
    elif share > 0.005:
        grade = _cap(grade, "C")
        causes.append(f"server errors were {share:.1%} of traffic")
    if f.get("repeated_reliability_problems"):
        _req_bool(f, "repeated_reliability_problems", "traffic")
        grade = _cap(grade, "D")
        causes.append("reliability problems repeated across days")
    if share404 > 0.10:
        grade = _cap(grade, "C")
        causes.append(f"'not found' responses were {share404:.1%} of traffic")
    if grade == "A" and (share > 0.001 or share404 > 0.05):
        grade = "B"
        causes.append(f"minor error noise above the clean band "
                      f"(server errors {share:.1%}, 'not found' {share404:.1%} of traffic)")
    return grade, causes


def compute_grades(findings):
    _validate_findings(findings)
    traffic, t_causes = grade_traffic(findings.get("traffic", {}))
    seo, s_causes = grade_seo_aeo(findings.get("seo_aeo") or {})
    security, sec_causes = grade_security(findings.get("security", {}))
    subs = {"traffic": traffic, "seo_aeo": seo, "security": security}
    graded = [g for g in subs.values() if g is not None]
    overall = GRADE_ORDER[min(GRADE_ORDER.index(g) for g in graded)] if graded else None
    ungraded = [k for k, g in subs.items() if g is None]
    sec = findings.get("security", {})
    unmeasured = [k for k in ("observatory_grade", "ssl_grade", "cert_days_left")
                  if sec.get(k) is None]
    if sec.get("critical") is None or sec.get("high") is None:
        unmeasured.append("alert_counts")
    return {"traffic": traffic, "seo_aeo": seo, "security": security,
            "overall": overall, "complete": not ungraded and not unmeasured,
            "ungraded_legs": ungraded, "unmeasured": unmeasured,
            "causes": {"traffic": t_causes, "seo_aeo": s_causes, "security": sec_causes}}


# ---------------------------------------------------------------- config

REQUIRED_CONFIG_FIELDS = [
    "site_name", "primary_host", "side_hosts", "edge_provider",
    "edge_credential", "code_host", "code_host_access", "repositories",
    "scanning", "hosting",
    "staging", "standing_items", "recipients", "owners", "sender",
    "sending_route", "schedule", "timezone", "brand",
]
EMPTY_NOT_ALLOWED = [f for f in REQUIRED_CONFIG_FIELDS if f != "standing_items"]
VALID_EDGE = {"cloudflare", "aws-cloudfront", "azure-front-door", "fastly",
              "akamai", "sucuri", "other", "none"}
VALID_CODEHOST = {"github", "gitlab", "bitbucket", "azure-devops",
                  "gitea", "codeberg", "other"}
# Hosts with no native Dependabot / CodeQL / secret-scanning equivalents.
NON_NATIVE_HOSTS = {"bitbucket", "azure-devops", "gitea", "codeberg"}
KNOWN_CONFIG_KEYS = set(REQUIRED_CONFIG_FIELDS) | {
    "code_host_instance", "code_host_addons", "code_host_access",
    "code_host_ci", "edge_tier", "notes", "app_platform",
    "site_backups"}

# Recognized scanning vocabulary. Anything else is rejected: an invented
# tool name in the config would otherwise certify coverage that does not
# exist. "none" is always available (it grades as a finding).
RECOGNIZED_SCANNING = {
    "dependencies": {"none", "dependabot", "renovate", "osv-scanner", "trivy",
                     "gitlab-dependency-scanning", "ghazdo-dependency-scanning",
                     "snyk", "mend", "sonarqube", "npm-audit", "pip-audit",
                     "cargo-audit", "bundler-audit", "composer-audit",
                     "owasp-dependency-check"},
    "sast": {"none", "codeql", "codeql-cli", "gitlab-sast", "ghazdo-codeql",
             "semgrep", "sonarqube", "snyk", "deepsource"},
    "secrets": {"none", "secret-scanning", "gitlab-secret-detection",
                "ghazdo-secret-scanning", "gitleaks", "trufflehog",
                "gitguardian", "snyk"},
}
GITHUB_ONLY_SERVICES = {
    "dependencies": {"dependabot"},
    "sast": {"codeql", "codeql-cli"},
    "secrets": {"secret-scanning"},
}


def _scan_value(v):
    return str(v).strip().lower()


def validate_config(cfg):
    return _validate_config(cfg)[0]


def validate_config_warnings(cfg):
    return _validate_config(cfg)[1]


def _validate_config(cfg):
    errors, warnings = [], []
    if not isinstance(cfg, dict):
        return ["config must be a JSON object"], warnings
    for field in REQUIRED_CONFIG_FIELDS:
        if field not in cfg:
            errors.append(f"missing required intake field: {field}")
    for field in EMPTY_NOT_ALLOWED:
        if field in cfg and (cfg[field] in (None, "", [], {})
                             or (isinstance(cfg[field], str) and not cfg[field].strip())):
            errors.append(f"intake field is empty: {field} "
                          f"(record 'none' explicitly where the answer is none)")
    for key in cfg:
        if key not in KNOWN_CONFIG_KEYS and not key.startswith("_"):
            warnings.append(f"unknown config key ignored: {key}")
    if "notes" in cfg and cfg["notes"] is not None and not isinstance(cfg["notes"], str):
        errors.append("notes must be a string (what the 'other' provider actually is)")
    if cfg.get("edge_provider") and _scan_value(cfg["edge_provider"]) not in VALID_EDGE:
        errors.append(f"edge_provider '{cfg['edge_provider']}' is not a known adapter "
                      f"(one of {sorted(VALID_EDGE)}); record 'other' plus a note instead of guessing")
    if cfg.get("code_host") and _scan_value(cfg["code_host"]) not in VALID_CODEHOST:
        errors.append(f"code_host '{cfg['code_host']}' is not a known adapter "
                      f"(one of {sorted(VALID_CODEHOST)})")
    if cfg.get("primary_host") is not None and not isinstance(cfg["primary_host"], str):
        errors.append("primary_host must be a hostname string")
    instance = cfg.get("code_host_instance")
    if instance is not None and _scan_value(instance) not in ("saas", "self-managed"):
        errors.append("code_host_instance must be 'saas' or 'self-managed'")
    if _scan_value(cfg.get("code_host", "")) in ("gitlab", "azure-devops", "gitea", "other") \
            and instance is None:
        warnings.append("code_host_instance is not recorded (saas vs self-managed "
                        "changes which scanners and tiers apply)")
    for provider_field in ("edge_provider", "code_host"):
        if _scan_value(cfg.get(provider_field, "")) == "other" and not str(cfg.get("notes") or "").strip():
            errors.append(f"{provider_field} is 'other': the notes field must say what "
                          f"the provider actually is (the skill has no adapter for it)")
    cred = _scan_value(cfg.get("edge_credential", ""))
    if _scan_value(cfg.get("edge_provider", "")) == "none" and cred and not cred.startswith("none"):
        warnings.append("edge_provider is 'none' but edge_credential names a credential; "
                        "record 'none' so the run does not go looking for an edge API")
    if _scan_value(cfg.get("edge_provider", "")) not in ("", "none") and cred == "none":
        warnings.append("an edge provider is recorded but edge_credential says 'none'; "
                        "the traffic leg will have no analytics source")
    tz = cfg.get("timezone")
    if tz:
        try:
            ZoneInfo(str(tz))
        except Exception:
            errors.append(f"timezone '{tz}' is not a valid IANA timezone")
    recips = cfg.get("recipients")
    if recips is not None:
        to = recips.get("to") if isinstance(recips, dict) else None
        if not isinstance(to, list) or not to or \
                any(not isinstance(x, str) or not x.strip() for x in to):
            errors.append("recipients.to must be a non-empty list of addresses: a "
                          "report with nobody to send to is not a valid config")
        cc = recips.get("cc") if isinstance(recips, dict) else None
        if cc is not None and (not isinstance(cc, list)
                               or any(not isinstance(x, str) or not x.strip() for x in cc)):
            errors.append("recipients.cc must be a list of addresses (or omitted)")
        # Shape, not just presence (round 12): an entry with no address
        # in it extracts to nothing on both sides of the header check
        # and 'agrees' vacuously.
        for field, entries in (("to", to), ("cc", cc)):
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, str) and entry.strip() \
                            and not _EMAIL_RE.search(entry):
                        errors.append(f"recipients.{field} entry '{entry}' "
                                      f"contains no email address")
    sender = cfg.get("sender")
    if sender is not None and (not isinstance(sender, str)
                               or not _EMAIL_RE.search(sender)):
        errors.append("sender must contain an email address (a bare name "
                      "cannot send)")
    items = cfg.get("standing_items")
    if items is not None and (not isinstance(items, list)
                              or any(not isinstance(x, str) or not x.strip()
                                     for x in items)):
        errors.append("standing_items must be a list of strings (the "
                      "closure annotation 'closed <date>' is appended to "
                      "the entry's text)")
    brand = cfg.get("brand")
    if brand is not None and (not isinstance(brand, dict)
                              or not str(brand.get("display_name") or "").strip()):
        errors.append("brand.display_name is required (the white-label name on the report)")
    scanning = cfg.get("scanning") or {}
    if not isinstance(scanning, dict):
        errors.append("scanning must be an object naming the tool per scan type")
        scanning = {}
    for kind in ("dependencies", "sast", "secrets"):
        if kind not in scanning:
            errors.append(f"scanning.{kind} is not recorded (name the tool, or 'none' "
                          f"so it grades as a finding)")
    host = _scan_value(cfg.get("code_host", ""))
    raw_addons = cfg.get("code_host_addons") or []
    if not isinstance(raw_addons, list) or \
            any(not isinstance(a, str) for a in raw_addons):
        errors.append("code_host_addons must be a list of strings (for example "
                      "['ghazdo']); a bare string does not activate an add-on")
        raw_addons = [a for a in raw_addons if isinstance(a, str)] \
            if isinstance(raw_addons, list) else []
    addons = {_scan_value(a) for a in raw_addons}
    for a in sorted(addons - {"ghazdo"}):
        errors.append(f"unknown code_host_addons entry '{a}': the only recognized "
                      f"add-on is 'ghazdo' (GitHub Advanced Security for Azure DevOps)")
    if "ghazdo" in addons and host != "azure-devops":
        errors.append("code_host_addons 'ghazdo' applies only with code_host "
                      "azure-devops (it is GitHub Advanced Security for Azure "
                      "DevOps); on this host it names nothing")
    ghazdo = host == "azure-devops" and "ghazdo" in addons
    for kind in ("dependencies", "sast", "secrets"):
        if kind not in scanning:
            continue
        if scanning.get(kind) is None:
            errors.append(f"scanning.{kind} is null: name the tool in place, or "
                          f"'none' so the absence is a deliberate record, not a "
                          f"malformed gather read as one")
            continue
        value = _scan_value(scanning.get(kind, ""))
        if value.startswith("gitlab-") and host != "gitlab":
            errors.append(f"scanning.{kind} '{scanning.get(kind)}' is a GitLab scanner "
                          f"name: it applies only with code_host gitlab. Record the "
                          f"host's own scanner, a pipeline fallback, or 'none'")
            continue
        if value == "native":
            label = {"dependencies": "dependency", "sast": "SAST",
                     "secrets": "secret"}[kind]
            errors.append(f"{host or 'the code host'} has no native {label} scanning "
                          f"service recorded under the name 'native': name the actual "
                          f"host scanner, the pipeline fallback, a commercial scanner, "
                          f"or 'none'")
            continue
        if value not in RECOGNIZED_SCANNING[kind]:
            errors.append(f"scanning.{kind} '{scanning.get(kind)}' is not a recognized "
                          f"tool name (one of {sorted(RECOGNIZED_SCANNING[kind])}); name "
                          f"the real tool, or 'none' so it grades as a finding")
            continue
        if value.startswith("ghazdo") and not ghazdo:
            errors.append(f"scanning.{kind} '{value}' is a GitHub Advanced Security for "
                          f"Azure DevOps tool: it applies only with code_host "
                          f"azure-devops and 'ghazdo' in code_host_addons")
            continue
        if value in GITHUB_ONLY_SERVICES[kind]:
            if host == "github":
                pass
            elif ghazdo and kind in ("sast", "secrets"):
                pass  # under GHAzDO, CodeQL and secret scanning are the real product
            elif host == "azure-devops" and kind == "sast":
                errors.append("azure-devops has no native SAST without GitHub Advanced "
                              "Security for Azure DevOps: add 'ghazdo' to "
                              "code_host_addons if it is licensed, or record the "
                              "pipeline fallback (semgrep)")
            else:
                specific = {
                    ("dependencies", "dependabot"):
                        f"{host} has no Dependabot: record the pipeline fallback "
                        f"(osv-scanner/trivy) or Renovate for updates, not 'dependabot'",
                    ("sast", "codeql"):
                        f"{host} has no native SAST/CodeQL service: record the pipeline "
                        f"fallback (semgrep) or a commercial scanner. CodeQL CLI on "
                        f"closed-source code generally requires GitHub Advanced Security "
                        f"licensing, so it is not the free fallback here",
                    ("sast", "codeql-cli"):
                        f"{host} has no native SAST/CodeQL service: record the pipeline "
                        f"fallback (semgrep) or a commercial scanner. CodeQL CLI on "
                        f"closed-source code generally requires GitHub Advanced Security "
                        f"licensing, so it is not the free fallback here",
                    ("secrets", "secret-scanning"):
                        f"{host} has no native secret scanning: record the pipeline "
                        f"fallback (gitleaks/trufflehog) or a commercial scanner",
                }
                errors.append(specific.get((kind, value),
                              f"{host} has no {value}: that is a GitHub service name. "
                              f"Record the host's own scanner, the pipeline fallback, "
                              f"a commercial scanner, or 'none'"))
    return errors, warnings


# ---------------------------------------------------------------- report

REQUIRED_SECTIONS = ["traffic", "seo", "security &", "website security scans",
                     "privacy", "recommendations"]
# The Sub-grades line is a single anchored line in the template's exact
# shape; prose mentions elsewhere in the document do not satisfy it.
# EVERY such line is checked: a second, contradictory line is a defect.
SUBGRADES_LINE = re.compile(
    r"sub-grades:[^\n]*?traffic\s*(?:&|and)\s*reliability\s+([A-Fa-f]|not available)\b"
    r"[^\n]*?seo\s*(?:/|&|and|-)\s*aeo\s+([A-Fa-f]|not available)\b"
    r"[^\n]*?security\s*(?:&|and)\s*code health\s+([A-Fa-f]|not available)\b")
# The template's per-section grade lines are headings ("## TRAFFIC & X --
# grade A", "## SEO / AEO -- grade B", "## SECURITY & CODE HEALTH --
# grade C"). Patterns are anchored to line starts so ordinary prose
# mentioning a grade is not mistaken for a section verdict.
SECTION_GRADE_PATTERNS = [
    ("traffic", re.compile(r"(?m)^(?:<h[1-6][^>]*>)?[#\s>*_-]*traffic\s*(?:&|and|-)[^\n]*?[\u2014\u2013:\u00b7-][^\n]*?grade\s*:?\s+([A-Fa-f])\b")),
    ("seo_aeo", re.compile(r"(?m)^(?:<h[1-6][^>]*>)?[#\s>*_-]*seo\s*(?:/|&|and|-)\s*aeo[^\n]*?[\u2014\u2013:\u00b7-][^\n]*?grade\s*:?\s+([A-Fa-f])\b")),
    ("security", re.compile(r"(?m)^(?:<h[1-6][^>]*>)?[#\s>*_-]*security\s*(?:&|and|-)[^\n]*?[\u2014\u2013:\u00b7-][^\n]*?grade\s*:?\s+([A-Fa-f])\b")),
]
# The first grade stated on a heading-shaped line governs that section:
# no tail discipline (rounds 9-11 showed every tail rule has a depth or
# shape boundary a stated grade can hide behind; the first-grade rule
# has none). The END set is the same rule for headings without a
# separator before 'grade'.
SECTION_GRADE_PATTERNS_END = [
    ("traffic", re.compile(r"(?m)^(?:<h[1-6][^>]*>)?[#\s>*_-]*traffic\s*(?:&|and|-)[^\n]*?grade\s*:?\s+([A-Fa-f])\b")),
    ("seo_aeo", re.compile(r"(?m)^(?:<h[1-6][^>]*>)?[#\s>*_-]*seo\s*(?:/|&|and|-)\s*aeo[^\n]*?grade\s*:?\s+([A-Fa-f])\b")),
    ("security", re.compile(r"(?m)^(?:<h[1-6][^>]*>)?[#\s>*_-]*security\s*(?:&|and|-)[^\n]*?grade\s*:?\s+([A-Fa-f])\b")),
]
OVERALL_PATTERN = re.compile(r"overall grade:\s*([A-Fa-f])\b")
CORRECTED_OVERALL_PATTERN = re.compile(r"corrected overall grade is\s+([A-Fa-f])\b")
CORRECTED_GRADES_LINE = re.compile(
    r"corrected grades:[^\n]*?traffic\s*(?:&|and)\s*reliability\s+([A-Fa-f]|not available)\b"
    r"[^\n]*?seo\s*(?:/|&|and|-)\s*aeo\s+([A-Fa-f]|not available)\b"
    r"[^\n]*?security\s*(?:&|and)\s*code health\s+([A-Fa-f]|not available)\b")


def _dedupe(items):
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def validate_report(text, findings=None, kind="edition"):
    problems = []
    low = text.lower()
    if kind == "correction":
        for section in ("correction", "what was wrong", "what is correct"):
            if section not in low:
                problems.append(f"missing correction section containing: {section}")
        corrected = CORRECTED_OVERALL_PATTERN.findall(low)
        if not corrected:
            problems.append("missing 'The corrected overall grade is X' line")
        if findings is not None:
            expected = compute_grades(findings)
            stray = [g.upper() for g in OVERALL_PATTERN.findall(low)
                     if expected["overall"] and g.upper() != expected["overall"]]
            if stray:
                problems.append(f"overall grade contradiction: the corrected "
                                f"findings compute {expected['overall']}, but the "
                                f"correction also states {sorted(set(stray))} on an "
                                f"'OVERALL GRADE:' line")
            if expected["overall"]:
                wrong = [g.upper() for g in corrected if g.upper() != expected["overall"]]
                if wrong:
                    problems.append(f"corrected grade contradiction: findings compute "
                                    f"{expected['overall']}, but the correction also "
                                    f"states {sorted(set(wrong))}")
            sub = CORRECTED_GRADES_LINE.findall(low)
            if not sub:
                problems.append("missing or malformed 'Corrected grades:' line "
                                "(expected 'Corrected grades: Traffic & reliability "
                                "<grade> · SEO/AEO <grade> · Security & code health "
                                "<grade>')")
            for line in sub:
                for idx, key in enumerate(("traffic", "seo_aeo", "security")):
                    want_grade = expected[key]
                    stated = None if line[idx] == "not available" else line[idx].upper()
                    if stated != want_grade:
                        problems.append(f"corrected sub-grade mismatch: findings "
                                        f"compute {key} {want_grade or 'not available'}"
                                        f", the correction states "
                                        f"{stated or 'not available'}")
            if not expected["complete"] and "incomplete" not in low:
                problems.append("the corrected findings grade is incomplete, but the "
                                "correction does not present it as incomplete")
        return _dedupe(problems)
    for section in REQUIRED_SECTIONS:
        if section not in low:
            problems.append(f"missing report section containing: {section}")
    overall_lines = OVERALL_PATTERN.findall(low)
    if findings is not None:
        expected = compute_grades(findings)
        if expected["overall"]:
            wrong = [g.upper() for g in overall_lines if g.upper() != expected["overall"]]
            if wrong:
                problems.append(f"overall grade contradiction: findings compute "
                                f"{expected['overall']}, but the report also states "
                                f"{sorted(set(wrong))}")
            elif not overall_lines:
                problems.append("missing 'OVERALL GRADE:' line")
        keys = ("traffic", "seo_aeo", "security")
        sub_lines = SUBGRADES_LINE.findall(low)
        for idx, key in enumerate(keys):
            want_grade = expected[key]
            if not sub_lines:
                problems.append("missing or malformed Sub-grades line (expected "
                                "'Sub-grades: Traffic & reliability <grade> - "
                                "SEO/AEO <grade> - Security & code health <grade>', "
                                "with 'not available' in the slot of an ungraded leg)")
                break
            for line in sub_lines:
                stated = None if line[idx] == "not available" else line[idx].upper()
                if stated != want_grade:
                    problems.append(f"sub-grade mismatch: findings compute {key} "
                                    f"{want_grade or 'not available'}, a Sub-grades "
                                    f"line states {stated or 'not available'}")
        for pat_key, pattern in SECTION_GRADE_PATTERNS + SECTION_GRADE_PATTERNS_END:
            want_grade = expected[pat_key]
            if want_grade is None:
                if pattern.findall(low):
                    problems.append(f"section grade contradiction: the {pat_key} "
                                    f"section states a letter grade, but the leg "
                                    f"is ungraded (not available)")
                continue
            for g in pattern.findall(low):
                if g.upper() != want_grade:
                    problems.append(f"section grade contradiction: the {pat_key} "
                                    f"section states grade {g.upper()}, findings "
                                    f"compute {want_grade}")
        if not expected["complete"]:
            if "not available" not in low:
                problems.append("the findings leave a leg ungraded or unmeasured, but "
                                "the report never says 'not available' for it")
            if "incomplete" not in low:
                problems.append("the findings grade is incomplete (a leg ungraded or "
                                "unmeasured), but the report does not present the "
                                "overall grade as incomplete")
    elif not overall_lines:
        problems.append("missing 'OVERALL GRADE:' line")
    return _dedupe(problems)


# ---------------------------------------------------------------- run check

def validate_run(cfg, findings, report_text, kind="edition"):
    """The cross-artifact check: config, findings, and report together.

    Each artifact validated alone can be internally consistent and still
    describe three different realities. This is the validation of record
    for an edition (or correction): the findings must not contradict the
    configured stack, and the report's sender and recipients must be the
    config's.
    """
    problems = []
    errors, warnings = _validate_config(cfg)
    problems.extend(f"config: {e}" for e in errors)
    if errors:
        # A structurally invalid config cannot be cross-checked: its
        # fields cannot be dereferenced safely, and its own error
        # list is the answer the operator needs.
        return _dedupe(problems), warnings
    try:
        compute_grades(findings)
    except InputError as e:
        problems.append(f"findings: {e}")
        return _dedupe(problems), warnings
    problems.extend(validate_report(report_text, findings, kind=kind))
    sec = findings.get("security", {})
    scanning = cfg.get("scanning") or {}
    if _scan_value(scanning.get("sast", "")) == "none" and sec.get("code_scanning_on"):
        problems.append("config/findings contradiction: scanning.sast is 'none' but "
                        "findings claim code_scanning_on is true")
    if _scan_value(scanning.get("secrets", "")) == "none" and sec.get("secret_scanning_on"):
        problems.append("config/findings contradiction: scanning.secrets is 'none' but "
                        "findings claim secret_scanning_on is true")
    # Scanner identity: the findings name the scanners that actually
    # produced the counts, and they must be the configured ones. A
    # fallback's output read under the native scanner's name is the
    # mislabel this catches. A kind is active when its evidence exists:
    # the *_on flag for sast/secrets, measured counts for dependencies.
    used = sec.get("scanners_used")
    if used is not None and not isinstance(used, dict):
        problems.append("findings scanners_used must be an object naming the "
                        "scanner per kind")
        used = None
    active = {"sast": bool(sec.get("code_scanning_on")),
              "secrets": bool(sec.get("secret_scanning_on")),
              "dependencies": any(sec.get(k) is not None for k in
                                  ("critical", "high", "medium", "low",
                                   "total_open"))}
    for kind_key in ("dependencies", "sast", "secrets"):
        configured = _scan_value(scanning.get(kind_key, ""))
        # The assertion layer (round 13): naming a scanner for a kind
        # the config records as 'none' is a contradiction even when the
        # kind carries no evidence this edition. A scanners_used value
        # of 'none' itself is the honest mirror of the config, not an
        # assertion (round 14, matching the record line's treatment).
        _asserted = _scan_value((used or {}).get(kind_key, ""))
        if configured == "none" and _asserted and _asserted != "none":
            problems.append(f"findings scanners_used names a {kind_key} "
                            f"scanner but the config records {kind_key} "
                            f"scanning as 'none'")
        if active[kind_key] and configured == "none":
            problems.append(f"findings carry {kind_key} evidence but the "
                            f"config records {kind_key} scanning as 'none'")
        if active[kind_key] and configured not in ("", "none"):
            named = _scan_value((used or {}).get(kind_key, ""))
            if not named:
                problems.append(f"findings carry {kind_key} evidence but "
                                f"scanners_used does not name the {kind_key} "
                                f"scanner that produced it")
            elif named != configured:
                problems.append(f"scanner identity mismatch: config records "
                                f"{kind_key} '{configured}' but findings say "
                                f"'{named}' ran")
    edge_none = _scan_value(cfg.get("edge_provider", "")) == "none"
    posture = _norm(sec.get("edge_posture"))
    if edge_none and posture != "none":
        problems.append("config/findings contradiction: edge_provider is 'none' but "
                        f"findings claim edge_posture '{posture}'")
    if not edge_none and posture == "none":
        problems.append("config/findings contradiction: an edge provider is "
                        "configured but findings claim edge_posture 'none'")
    # Editions only (a correction is a short notice, not a full
    # edition: it carries no header block and no scanner sections, and
    # its recipients are governed by the send discipline, not by a
    # header in the file): the report must name each configured
    # scanners on its 'Scanners of record:' line (the credit of record,
    # cross-checked word by word against the configured scanners), and
    # its header's address sets must equal the config's exactly: no
    # swaps, no additions, no prose-only presence.
    if kind != "correction":
        problems.extend(_record_line_problems(report_text, scanning))
        problems.extend(_header_problems(cfg, report_text))
    return _dedupe(problems), warnings


# Display-name forms a report may credit a scanner by. The config and
# findings speak the vocabulary tokens ('gitlab-sast'); the report's
# Scanners of record line speaks prose ('GitLab SAST'). Matching is by
# whole words in sequence, so 'sastra', 'audited', and negated or
# incidental body mentions cannot satisfy the credit of record; the
# identity enforcement behind the line lives in findings.scanners_used.
SCANNER_DISPLAY_ALIASES = {
    "gitlab-dependency-scanning": ["gitlab dependency scanning", "dependency scanning"],
    "gitlab-sast": ["gitlab sast", "sast"],
    "gitlab-secret-detection": ["gitlab secret detection", "secret detection"],
    "ghazdo-dependency-scanning": ["dependency scanning",
                                   "github advanced security for azure devops",
                                   "github advanced security"],
    "ghazdo-codeql": ["codeql", "github advanced security codeql",
                      "github advanced security for azure devops codeql"],
    "ghazdo-secret-scanning": ["secret scanning",
                               "github advanced security secret scanning"],
    "secret-scanning": ["secret scanning"],
    "codeql-cli": ["codeql cli", "codeql"],
    "osv-scanner": ["osv scanner"],
    "npm-audit": ["npm audit"],
    "pip-audit": ["pip audit"],
    "cargo-audit": ["cargo audit"],
    "bundler-audit": ["bundler audit"],
    "composer-audit": ["composer audit"],
    "owasp-dependency-check": ["owasp dependency check", "dependency check"],
}


# Every scanner name the tool knows, for the 'none'-kind credit test:
# vocabulary tokens and their display aliases, minus the bare role
# phrases (a segment naming only the kind credits no scanner).
_ROLE_ONLY_NAMES = {"dependency scanning", "code scanning",
                    "secret scanning", "sast", "secret detection"}
_KNOWN_SCANNER_NAMES = sorted(
    ({_scan_value(k) for k in SCANNER_DISPLAY_ALIASES}
     | {_scan_value(a) for v in SCANNER_DISPLAY_ALIASES.values() for a in v}
     | {_scan_value(t) for names in RECOGNIZED_SCANNING.values()
        for t in names})
    - _ROLE_ONLY_NAMES - {"", "none"},
    key=lambda s: -len(s.split()))


def _words(text):
    return re.findall(r"[a-z0-9]+", (text or "").lower())


def _contains_words(words, phrase_words):
    if not phrase_words or len(phrase_words) > len(words):
        return False
    return any(words[i:i + len(phrase_words)] == phrase_words
               for i in range(len(words) - len(phrase_words) + 1))


_NEGATORS = {"not", "never", "no", "none", "nor"}
_NEG_FOLLOW = {"used", "use", "ran", "run", "running", "employed",
               "selected", "chosen", "enabled", "deployed", "configured",
               "installed", "active"}


def _phrase_present(words, phrase_words):
    """A phrase counts only where at least one occurrence is not negated.
    Negation is a negator within eight words before the phrase ('not one
    single one of the following X'), or a negator within two words after
    it followed by a verb of use ('X was never enabled'). The affirming
    construction 'not only X' is removed before checking. Callers pass
    one clause at a time, so a negation in another clause cannot bleed
    across."""
    cleaned = []
    i = 0
    while i < len(words):
        if words[i] == "not" and i + 1 < len(words) and words[i + 1] == "only":
            i += 2
            continue
        cleaned.append(words[i])
        i += 1
    words = cleaned
    n = len(phrase_words)
    for i in range(len(words) - n + 1):
        if words[i:i + n] != phrase_words:
            continue
        if any(w in _NEGATORS for w in words[max(0, i - 8):i]):
            continue
        after = words[i + n:i + n + 8]
        negated_after = any(
            after[k] in _NEGATORS
            and any(w in _NEG_FOLLOW for w in after[k + 1:k + 3])
            for k in range(len(after)))
        if not negated_after:
            return True
    return False


def _line_names_scanner(line, token):
    phrases = [_words(token.replace("-", " "))]
    phrases += [_words(a) for a in SCANNER_DISPLAY_ALIASES.get(token, [])]
    for clause in re.split(r"[.;]", line or ""):
        words = _words(clause)
        if any(_phrase_present(words, p) for p in phrases):
            return True
    return False


def _credited_name(segment):
    """The scanner an attribution segment actually credits: the text
    after the last ' by ', the parenthetical in the 'role (Name)' form,
    or the text after the segment's label colon. For the secrets kind
    the scanner's word form IS the role phrase ('secret scanning'), so
    the whole segment cannot be the test; the credited name is."""
    seg = segment or ""
    if seg.lower().startswith("scanners of record:"):
        seg = seg.split(":", 1)[1]
    low = seg.lower()
    if " by " in low:
        return seg[low.rfind(" by ") + 4:]
    m = re.search(r"\(([^)]*)\)", seg)
    if m:
        return m.group(1)
    if ":" in seg:
        return seg.split(":", 1)[1]
    return seg


_ROLE_WORDS = {
    "dependencies": ("dependency", "dependencies"),
    "sast": ("sast", "code scanning"),
    "secrets": ("secret", "secrets"),
}


def _record_line_problems(report_text, scanning):
    """The Scanners of record line is the report's scanner credit. Every
    occurrence must agree (a contradictory second line fails), quoted
    code blocks do not count, a wrapped line is joined with its
    continuations, and where the line attributes kinds to scanners by
    role ('code scanning by X'), each role's segment must name the
    configured scanner for that kind."""
    text = re.sub(r"```.*?```", "", report_text, flags=re.S)
    lines = text.splitlines()
    records = []
    for i, line in enumerate(lines):
        bare = re.sub(r"^[\s\-\*>#•]+", "", line).lower()
        if bare.startswith("scanners of record:"):
            logical = line
            for nxt in lines[i + 1:i + 4]:
                nbare = re.sub(r"^[\s\-\*>#•]+", "", nxt).lower()
                if not nxt.strip() or nbare.startswith(
                        ("scanners of record:", "from:", "to:", "cc:",
                         "subject:", "overall grade", "sub-grades")):
                    break
                # A continuation is a wrap: indented, or starting with a
                # lowercase word mid-phrase. A fresh capitalized sentence
                # is prose, not part of the credit line.
                first = nxt.strip().split(None, 1)[0] if nxt.strip() else ""
                if not (nxt[:1] in (" ", "\t") or (first and first[:1].islower())):
                    break
                logical += " " + nxt.strip()
            records.append(logical)
    if not records:
        return ["report has no 'Scanners of record:' line: the template's "
                "line naming the scanner per kind is the credit of record "
                "and is required"]
    problems = []
    for kind_key in ("dependencies", "sast", "secrets"):
        configured = _scan_value(scanning.get(kind_key, ""))
        if configured == "none":
            # Assertion layer (round 13): the line must not credit any
            # scanner for a kind the config records as 'none'. What
            # counts as a credit (round 15): a KNOWN scanner name
            # present in the credit target with the same negation
            # awareness as the configured path — a bare role phrase,
            # a negated mention, or a parenthetical remark names no
            # scanner and is not a credit. Credit shapes mirror the
            # configured path: attribution segments test their credited
            # name, a shape-less role segment is itself the target.
            for record in records:
                segments = re.split(r"[,;·|•]|\band\b", record)
                role_segments = [seg for seg in segments
                                 if any(rw in seg.lower()
                                        for rw in _ROLE_WORDS[kind_key])]
                attributions = [seg for seg in role_segments
                                if " by " in seg.lower() or ":" in seg
                                or "(" in seg]
                targets = [_credited_name(seg) for seg in attributions] \
                    if attributions else role_segments
                credited_hit = None
                for t in targets:
                    words = _words(t)
                    for cand in _KNOWN_SCANNER_NAMES:
                        if _phrase_present(words, cand.split()):
                            credited_hit = cand
                            break
                    if credited_hit:
                        break
                if credited_hit:
                    problems.append(
                        f"a Scanners of record line credits a "
                        f"{kind_key} scanner ('{credited_hit}') but the "
                        f"config records {kind_key} scanning as 'none'")
                    break
            continue
        if configured == "":
            continue
        for record in records:
            segments = re.split(r"[,;·|•]|\band\b", record)
            role_segments = [seg for seg in segments
                             if any(rw in seg.lower()
                                    for rw in _ROLE_WORDS[kind_key])]
            attributions = [seg for seg in role_segments
                            if " by " in seg.lower() or ":" in seg
                            or "(" in seg]
            targets = [_credited_name(seg) for seg in attributions] \
                if attributions else \
                ([" ".join(role_segments)] if role_segments else [record])
            if not all(_line_names_scanner(t, configured) for t in targets):
                problems.append(
                    f"a Scanners of record line does not name the configured "
                    f"{kind_key} scanner ('{configured}'), in vocabulary or "
                    f"display-name form")
                break
    return problems


_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _emails(text):
    return {m.group(0).lower() for m in _EMAIL_RE.finditer(text or "")}


def _addressish(line):
    """A header continuation line: every token is part of an address
    list (an address, a separator, or a capitalized name word). A prose
    line, with its lowercase sentence words, is not; neither is a
    label-shaped line ('Notes: someone@example.com'), which starts a
    new field rather than continuing an address list."""
    if re.match(r"^[A-Za-z][\w .-]*:\s", line.strip()):
        return False
    tokens = [t for t in re.split(r"\s+", line.strip()) if t]
    if any("@" not in t and t.strip(",;·|").isupper()
           and len(t.strip(",;·|")) >= 3 for t in tokens):
        return False  # all-caps prose ('COPIES TO ...'), not an address list
    prose_lead = {"copies", "copy", "to", "from", "cc", "subject", "notes",
                  "note", "date", "sent", "attn", "regarding", "contact",
                  "please", "reviewed", "review", "loop", "distribution"}
    for tok in tokens:
        if "@" in tok:
            break
        if tok.strip(",;·|").lower() in prose_lead:
            return False  # prose lead-in ('Copies To ...'), not an address list
    if not tokens:
        return False
    for tok in tokens:
        core = tok.strip(",;·|")
        if "@" in core or core in ("and", "&"):
            continue
        if core[:1].isupper():
            continue
        return False
    return True


def _header_problems(cfg, report_text):
    """Parse the report's From/To/Cc header and compare address sets
    exactly against the config. The header block runs from the first
    label to the first blank line (within the first 15 lines); labels
    may be bulleted and may sit on one line ('From: X · To: Y'), one
    per line in any order, or alone with addresses on the following
    lines. A label's addresses are its own text plus following
    address-shaped lines only, so body prose after the header can
    neither pollute a set nor satisfy one.
    """
    all_lines = report_text.splitlines()
    start = next((i for i, ln in enumerate(all_lines[:15])
                  if re.search(r"(?i)(?:^|[·|\n])\s*(?:[-*•>]\s*)?"
                               r"(from|to|cc)\s*:", ln)), None)
    if start is None:
        return ["report header not found: the edition must carry its From/To "
                "header copied from the config (recipients are never re-typed)"]
    block_lines = []
    for ln in all_lines[start:start + 40]:
        if not ln.strip():
            break
        block_lines.append(ln)
    block = "\n".join(block_lines)
    labels = list(re.finditer(
        r"(?im)(?:^|[·|\n])\s*(?:[-*•>]\s*)?(from|to|cc)\s*:", block))
    segments = {}
    for i, m in enumerate(labels):
        end = labels[i + 1].start() if i + 1 < len(labels) else len(block)
        seg_lines = block[m.end():end].splitlines()
        kept = seg_lines[:1]
        for extra in seg_lines[1:]:
            if re.match(r"^[A-Za-z][\w .-]*:\s", extra.strip()):
                continue  # an intervening labelled line is skipped, not read
            if _addressish(extra):
                kept.append(extra)
            else:
                break
        segments.setdefault(m.group(1).lower(), set()).update(
            _emails("\n".join(kept)))
    if "from" not in segments or "to" not in segments:
        return ["report header not found: the edition must carry its From/To "
                "header copied from the config (recipients are never re-typed)"]
    problems = []
    want_from = _emails(str(cfg.get("sender") or ""))
    if want_from and segments["from"] != want_from:
        problems.append(f"header From set {sorted(segments['from'])} does not equal "
                        f"the configured sender {sorted(want_from)}")
    recips = cfg.get("recipients") or {}
    want_to = _emails(", ".join(recips.get("to") or []))
    if segments["to"] != want_to:
        problems.append(f"header To set {sorted(segments['to'])} does not equal "
                        f"the configured recipients {sorted(want_to)}: no swaps, "
                        f"no additions, no re-typing")
    want_cc = _emails(", ".join(recips.get("cc") or []))
    got_cc = segments.get("cc", set())
    if got_cc != want_cc:
        problems.append(f"header Cc set {sorted(got_cc)} does not equal the "
                        f"configured Cc {sorted(want_cc)}")
    return problems


# ---------------------------------------------------------------- CLI

def _reject_constant(name):
    raise InputError(f"invalid JSON constant {name}: NaN and Infinity are not "
                     f"measurements; use a number or null")


def _load_json(path):
    if path.endswith((".yaml", ".yml")):
        raise InputError("YAML is a human-readable mirror only. The config of record "
                         "is JSON: convert the file to JSON (same fields) and re-run.")
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh, parse_constant=_reject_constant)
    except FileNotFoundError:
        raise InputError(f"file not found: {path}")
    except (OSError, UnicodeDecodeError) as e:
        raise InputError(f"cannot read {path}: {e}")
    except json.JSONDecodeError as e:
        raise InputError(f"invalid JSON in {path}: {e}")
    if not isinstance(data, dict):
        raise InputError(f"{path} must contain a JSON object")
    return data


def _split_kind(args):
    """Split an optional '--kind correction|edition' pair out of the
    argument list. Only the flag's own value is consumed, so a findings
    file literally named 'correction' stays a positional argument."""
    kind = "edition"
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--kind" and i + 1 < len(args):
            kind = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1
    return kind, rest


def main(argv):
    try:
        if len(argv) < 2 or argv[1] in ("-h", "--help"):
            print(__doc__)
            return 0 if len(argv) >= 2 else 1
        cmd = argv[1]
        if cmd == "headers" and len(argv) == 3:
            result = check_headers(fetch_headers(argv[2]))
            print(json.dumps(result, indent=2))
            return 0 if result["csp"] == "enforcing" else 1
        if cmd == "grade" and len(argv) == 3:
            grades = compute_grades(_load_json(argv[2]))
            print(json.dumps(grades, indent=2))
            return 0
        if cmd == "burst" and len(argv) == 3:
            data = _load_json(argv[2])
            try:
                print(classify_error_burst(data["total_errors"], data["top_single_ip_errors"],
                                           data["primary_host_errors"],
                                           data.get("top_single_host_errors")))
            except KeyError as e:
                raise InputError(f"burst file is missing the key {e}")
            return 0
        if cmd == "validate-config" and len(argv) == 3:
            cfg = _load_json(argv[2])
            errors, warnings = _validate_config(cfg)
            for w in warnings:
                print("WARNING:", w)
            for e in errors:
                print("ERROR:", e)
            if not errors:
                print("OK: config is complete and valid")
            return 1 if errors else 0
        if cmd == "validate-report" and len(argv) in (3, 4, 5, 6):
            kind, args = _split_kind(argv[2:])
            try:
                text = open(args[0], encoding="utf-8-sig").read()
            except FileNotFoundError:
                raise InputError(f"file not found: {args[0]}")
            except (OSError, UnicodeDecodeError) as e:
                raise InputError(f"cannot read {args[0]}: {e}")
            except IndexError:
                print(__doc__)
                return 1
            findings = _load_json(args[1]) if len(args) > 1 else None
            problems = validate_report(text, findings, kind=kind)
            for p in problems:
                print("PROBLEM:", p)
            if not problems:
                if findings is None:
                    print("OK: report structure only (no findings supplied; "
                          "grades were not checked). This is not an edition "
                          "validation: run check-run before sending")
                else:
                    print("OK: report structure and grades agree with the findings")
            return 1 if problems else 0
        if cmd == "check-run" and len(argv) in (5, 6, 7):
            kind, args = _split_kind(argv[2:])
            if len(args) != 3:
                print(__doc__)
                return 1
            cfg = _load_json(args[0])
            findings = _load_json(args[1])
            try:
                text = open(args[2], encoding="utf-8-sig").read()
            except FileNotFoundError:
                raise InputError(f"file not found: {args[2]}")
            except (OSError, UnicodeDecodeError) as e:
                raise InputError(f"cannot read {args[2]}: {e}")
            problems, warnings = validate_run(cfg, findings, text, kind=kind)
            for w in warnings:
                print("WARNING:", w)
            for p in problems:
                print("PROBLEM:", p)
            if not problems:
                print("OK: config, findings and report agree (check-run passed)")
            return 1 if problems else 0
        print(__doc__)
        return 1
    except InputError as e:
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
