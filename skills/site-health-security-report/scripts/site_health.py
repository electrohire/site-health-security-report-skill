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
manufacture an A. (Red-team findings 1, 2, 7, release 1.0.0.)

CLI:
  site_health.py headers https://example.com
  site_health.py grade findings.json
  site_health.py burst burst.json
  site_health.py validate-config config.json     (JSON is the config of record)
  site_health.py validate-report report.md findings.json
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
    for k, v in headers.items():
        val = str(v).strip()
        if val:
            lower[str(k).lower()] = val
    notes = []
    if "strict-transport-security" in lower:
        m = re.search(r"max-age\s*=\s*(\d+)", lower["strict-transport-security"])
        if m and int(m.group(1)) == 0:
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
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "site-health-report/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
            return dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        return dict(e.headers.items())
    except (urllib.error.URLError, ssl.SSLError, OSError) as e:
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
    if total_errors <= 0:
        return "distributed"
    ip_share = top_single_ip_errors / total_errors
    primary_share = primary_host_errors / total_errors
    if ip_share >= 0.60:
        return "concentrated-event"
    if primary_share >= 0.50:
        return "outage"
    if top_single_host_errors is not None and top_single_host_errors / total_errors >= 0.60:
        return "concentrated-event"
    return "distributed"


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
    _req_count(s, "critical", "security")
    _req_count(s, "high", "security")
    _req_bool(s, "code_scanning_on", "security")
    _req_bool(s, "secret_scanning_on", "security")
    if _norm(s.get("csp")) not in ("enforcing", "report-only", "missing"):
        raise InputError(f"security.csp must be 'enforcing', 'report-only', or 'missing' "
                         f"(measured, never omitted), got {s.get('csp')!r}")
    if _norm(s.get("dmarc")) not in ("reject", "quarantine", "none", "missing"):
        raise InputError(f"security.dmarc must be 'reject', 'quarantine', 'none', or "
                         f"'missing' (measured, never omitted), got {s.get('dmarc')!r}")
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
    critical = _req_count(f, "critical", "security")
    high = _req_count(f, "high", "security")
    if critical > 0:
        grade = _cap(grade, "D")
        causes.append(f"{critical} critical dependency/code alert(s) open")
    if high > 0:
        grade = _cap(grade, "C")
        causes.append(f"{high} high-severity alert(s) open")
    cert_days = f.get("cert_days_left")
    if cert_days is not None and (not _is_number(cert_days)):
        raise InputError(f"security.cert_days_left must be a number or null, got {cert_days!r}")
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
    named_caps = [
        (not f["code_scanning_on"], "code scanning is dark on at least one product repo"),
        (not f["secret_scanning_on"], "secret scanning is dark on at least one product repo"),
        (secret_alerts > 0, "secret-scanning alert(s) open"),
        (_norm(f.get("csp")) == "report-only", "Content-Security-Policy is report-only, not enforcing"),
        (_norm(f.get("csp")) == "missing", "no Content-Security-Policy header"),
        (_norm(f.get("observatory_grade"), upper=True) in ("D", "F"),
         f"Mozilla Observatory grade {_norm(f.get('observatory_grade'), upper=True)}"),
        (_norm(f.get("ssl_grade"), upper=True) in ("C", "D", "F", "T", "M"),
         f"SSL Labs grade {_norm(f.get('ssl_grade'), upper=True)} is below B"),
        (cert_cause is not None, cert_cause),
        (_norm(f.get("dmarc")) in ("none", "missing"), f"DMARC policy is {_norm(f.get('dmarc'))}"),
        (privacy_failures > 0, f"{privacy_failures} privacy/AI spot check(s) failing"),
        (ci_blocked, "CI/CD cannot run, so the security pipeline cannot run either"),
    ]
    for hit, text in named_caps:
        if hit:
            grade = _cap(grade, "C")
            causes.append(text)
    return grade, causes


def grade_seo_aeo(f):
    scores = [s for s in (_opt_score(f, "aeo_score", "seo_aeo"),
                          _opt_score(f, "seo_score", "seo_aeo")) if s is not None]
    if not scores:
        return None, ["no SEO/AEO score could be produced this run; the leg is "
                      "reported as not available and the overall grade is incomplete"]
    grade = _band_from_score(min(scores))
    return grade, ([] if grade in ("A", "B") else [f"lowest SEO/AEO score is {min(scores):g}"])


def grade_traffic(f):
    causes = []
    if _req_bool(f, "outage_confirmed", "traffic"):
        return "F", ["the primary host was confirmed down (burst rule applied)"]
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
    return {"traffic": traffic, "seo_aeo": seo, "security": security,
            "overall": overall, "complete": not ungraded,
            "ungraded_legs": ungraded,
            "causes": {"traffic": t_causes, "seo_aeo": s_causes, "security": sec_causes}}


# ---------------------------------------------------------------- config

REQUIRED_CONFIG_FIELDS = [
    "site_name", "primary_host", "side_hosts", "edge_provider",
    "edge_credential", "code_host", "repositories", "scanning", "hosting",
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
KNOWN_CONFIG_KEYS = set(REQUIRED_CONFIG_FIELDS) | {"code_host_instance", "notes"}


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
        if field in cfg and cfg[field] in (None, "", [], {}):
            errors.append(f"intake field is empty: {field} "
                          f"(record 'none' explicitly where the answer is none)")
    for key in cfg:
        if key not in KNOWN_CONFIG_KEYS:
            warnings.append(f"unknown config key ignored: {key}")
    if cfg.get("edge_provider") and _scan_value(cfg["edge_provider"]) not in VALID_EDGE:
        errors.append(f"edge_provider '{cfg['edge_provider']}' is not a known adapter "
                      f"(one of {sorted(VALID_EDGE)}); record 'other' plus a note instead of guessing")
    if cfg.get("code_host") and _scan_value(cfg["code_host"]) not in VALID_CODEHOST:
        errors.append(f"code_host '{cfg['code_host']}' is not a known adapter "
                      f"(one of {sorted(VALID_CODEHOST)})")
    tz = cfg.get("timezone")
    if tz:
        try:
            ZoneInfo(str(tz))
        except Exception:
            errors.append(f"timezone '{tz}' is not a valid IANA timezone")
    recips = cfg.get("recipients")
    if recips is not None:
        if not isinstance(recips, dict) or not recips.get("to"):
            errors.append("recipients.to must be a non-empty list: a report with "
                          "nobody to send to is not a valid config")
    brand = cfg.get("brand")
    if brand is not None and (not isinstance(brand, dict) or not brand.get("display_name")):
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
    if host in NON_NATIVE_HOSTS:
        dep = _scan_value(scanning.get("dependencies", ""))
        sast = _scan_value(scanning.get("sast", ""))
        sec = _scan_value(scanning.get("secrets", ""))
        if dep == "dependabot":
            errors.append(f"{host} has no Dependabot: record the pipeline fallback "
                          f"(osv-scanner/trivy) or Renovate for updates, not 'dependabot'")
        if sast in ("native", "codeql"):
            errors.append(f"{host} has no native SAST/CodeQL service: record the pipeline "
                          f"fallback (semgrep) or a commercial scanner. CodeQL CLI on "
                          f"closed-source code generally requires GitHub Advanced Security "
                          f"licensing, so it is not the free fallback here")
        if sec in ("secret-scanning", "secret scanning"):
            errors.append(f"{host} has no native secret scanning: record the pipeline "
                          f"fallback (gitleaks/trufflehog) or a commercial scanner")
    return errors, warnings


# ---------------------------------------------------------------- report

REQUIRED_SECTIONS = ["traffic", "seo", "security &", "website security scans",
                     "privacy", "recommendations"]
SUBGRADE_PATTERNS = [
    ("traffic", r"traffic & reliability\s+([A-Fa-f])\b"),
    ("seo_aeo", r"seo/aeo\s+([A-Fa-f])\b"),
    ("security", r"security & code health\s+([A-Fa-f])\b"),
]


def validate_report(text, findings=None):
    problems = []
    low = text.lower()
    for section in REQUIRED_SECTIONS:
        if section not in low:
            problems.append(f"missing report section containing: {section}")
    if "overall grade:" not in low:
        problems.append("missing 'OVERALL GRADE:' line")
    if findings is not None:
        expected = compute_grades(findings)
        if expected["overall"]:
            want = f"overall grade: {expected['overall']}".lower()
            if want not in low:
                problems.append(f"grade mismatch: findings compute overall "
                                f"{expected['overall']}, the report does not state it")
        for key, pattern in SUBGRADE_PATTERNS:
            want_grade = expected[key]
            m = re.search(pattern, low)
            if want_grade is None:
                if m:
                    problems.append(f"sub-grade mismatch: the {key} leg is ungraded "
                                    f"(not available) but the report states a grade for it")
                continue
            if not m:
                problems.append(f"missing sub-grade line for {key} "
                                f"(expected '... {want_grade}' in the Sub-grades line)")
            elif m.group(1).upper() != want_grade:
                problems.append(f"sub-grade mismatch: findings compute {key} "
                                f"{want_grade}, the report states {m.group(1).upper()}")
        if not expected["complete"]:
            if "not available" not in low:
                problems.append("the findings leave a leg ungraded, but the report "
                                "never says 'not available' for it")
    return problems


# ---------------------------------------------------------------- CLI

def _load_json(path):
    if path.endswith((".yaml", ".yml")):
        raise InputError("YAML is a human-readable mirror only. The config of record "
                         "is JSON: convert the file to JSON (same fields) and re-run.")
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise InputError(f"file not found: {path}")
    except json.JSONDecodeError as e:
        raise InputError(f"invalid JSON in {path}: {e}")
    if not isinstance(data, dict):
        raise InputError(f"{path} must contain a JSON object")
    return data


def main(argv):
    try:
        if len(argv) < 2:
            print(__doc__)
            return 1
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
        if cmd == "validate-report" and len(argv) in (3, 4):
            try:
                text = open(argv[2]).read()
            except FileNotFoundError:
                raise InputError(f"file not found: {argv[2]}")
            findings = _load_json(argv[3]) if len(argv) == 4 else None
            problems = validate_report(text, findings)
            for p in problems:
                print("PROBLEM:", p)
            if not problems:
                print("OK: report structure and grades agree with the findings")
            return 1 if problems else 0
        print(__doc__)
        return 1
    except InputError as e:
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
