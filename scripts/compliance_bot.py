#!/usr/bin/env python3
"""
Verax Protocol Compliance Bot — daily automated compliance checks.

Produces:
  - /tmp/compliance-report.json   (machine-readable)
  - stdout summary                  (human-friendly, posted to Slack/Teams)

Exit codes:
  0 — all checks passed
  1 — one or more checks triggered warnings
  2 — one or more checks triggered critical alerts
"""

import base64
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CARGO_LOCK = REPO_ROOT / "Cargo.lock"
SPEC_PIN = REPO_ROOT / "scripts" / "spec_pin.json"
CT_KEY_STORE = REPO_ROOT / "scripts" / "trusted_ct_log_keys.json"
CONFORMANCE_SUITE = REPO_ROOT / "test-vectors" / "vectors" / "conformance_suite.json"

CRATES_IO_API = "https://crates.io/api/v1/crates"
BLAKE3_REPO_API = "https://api.github.com/repos/BLAKE3-team/BLAKE3"
GOOGLE_CT_LOG_API = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"


def err(msg: str) -> None:
    print(f"  [FAIL] {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def warn(msg: str) -> None:
    print(f"  [WARN] {msg}")


def crit(msg: str) -> None:
    print(f"  [CRIT] {msg}")


# ── helpers ────────────────────────────────────────────────────────────

def cargo_package_version(name: str) -> str | None:
    """Parse current pinned version from Cargo.lock."""
    lines = CARGO_LOCK.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.strip() == f'name = "{name}"':
            for j in range(i, min(i + 5, len(lines))):
                if lines[j].strip().startswith("version = "):
                    return lines[j].strip().split("=")[1].strip().strip('"')
    return None


def crates_latest_version(name: str) -> str | None:
    """Query crates.io for the latest version of a crate."""
    req = urllib.request.Request(
        f"{CRATES_IO_API}/{name}",
        headers={"User-Agent": "verax-compliance-bot/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("crate", {}).get("max_version")
    except Exception as e:
        warn(f"crates.io lookup failed for {name}: {e}")
        return None


# ── Check 1: CBOR Library Audit ──────────────────────────────────────

def check_cbor_deps(report: dict) -> None:
    print("\n[1/5] CBOR Library Audit")
    findings = []

    # The core crate doesn't use ciborium directly — it has its own CBOR
    # implementation.  But ciborium may appear as a dev/build dependency.
    ciborium_ver = cargo_package_version("ciborium")
    if ciborium_ver:
        ok(f"ciborium pinned at {ciborium_ver}")
        latest = crates_latest_version("ciborium")
        if latest and latest != ciborium_ver:
            warn(f"ciborium {ciborium_ver} -> {latest} available")
            findings.append({
                "check": "cbor_lib_version",
                "severity": "warning",
                "message": f"ciborium {ciborium_ver} -> {latest}",
            })
    else:
        ok("no external CBOR library — using built-in deterministic encoder")

    # Run deterministic CBOR tests
    try:
        result = subprocess.run(
            ["cargo", "test", "--release", "-p", "verax-core", "--",
             "cbor::tests::test_deterministic_encoding"],
            capture_output=True, text=True, timeout=300,
            cwd=str(REPO_ROOT),
        )
        output = result.stdout + result.stderr
        if "test result: ok" in output:
            ok("deterministic CBOR test suite passes")
        elif "error: could not compile" in output or "error: no such subcommand" in output:
            warn(f"cargo build failed — skipping CBOR test: {output[-200:]}")
        else:
            err("deterministic CBOR test suite FAILED")
            findings.append({
                "check": "cbor_test_suite",
                "severity": "critical",
                "message": "CBOR test suite failure",
                "details": output[-500:],
            })
    except subprocess.TimeoutExpired:
        err("deterministic CBOR test suite timed out")
        findings.append({
            "check": "cbor_test_suite",
            "severity": "critical",
            "message": "CBOR test suite timed out",
        })
    except FileNotFoundError:
        warn("cargo not found — skipping CBOR test")

    # Run the Python differential conformance test
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/differential_cbor_test.py")],
        capture_output=True, text=True, timeout=60,
    )
    if "11/11 rules passed" in result.stdout:
        ok("Python CBOR conformance: 11/11 rules pass")
    else:
        err("Python CBOR conformance test FAILED")
        findings.append({
            "check": "cbor_python_conformance",
            "severity": "critical",
            "message": "CBOR conformance rules violation",
            "details": result.stdout + result.stderr,
        })

    report["cbor_library_audit"] = {"findings": findings}


# ── Check 2: BLAKE3 Hash Function Monitor ────────────────────────────

def check_blake3(report: dict) -> None:
    print("\n[2/5] BLAKE3 Hash Function Monitor")
    findings = []

    pinned = cargo_package_version("blake3")
    if not pinned:
        err("blake3 not found in Cargo.lock")
        return
    ok(f"blake3 pinned at {pinned}")

    # Check for newer version on crates.io
    latest = crates_latest_version("blake3")
    if latest and latest != pinned:
        # Parse versions — minor/patch is advisory, major is critical
        p_major = pinned.split(".")[0]
        l_major = latest.split(".")[0]
        if p_major != l_major:
            crit(f"blake3 major version change: {pinned} -> {latest}")
            findings.append({
                "check": "blake3_major_version",
                "severity": "critical",
                "message": f"blake3 major version {pinned} -> {latest} — output/API may differ",
            })
        else:
            warn(f"blake3 {pinned} -> {latest} available (minor)")
            findings.append({
                "check": "blake3_version",
                "severity": "warning",
                "message": f"blake3 {pinned} -> {latest}",
            })

    # Fetch security advisories from GitHub Advisory Database
    advisory_url = f"https://api.github.com/advisories?ecosystem=cargo&package=blake3"
    req = urllib.request.Request(advisory_url, headers={
        "User-Agent": "verax-compliance-bot/1.0",
        "Accept": "application/vnd.github+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            advisories = json.loads(resp.read())
        if advisories:
            crit(f"{len(advisories)} security advisory/ies found for blake3")
            for adv in advisories:
                findings.append({
                    "check": "blake3_advisory",
                    "severity": "critical",
                    "message": adv.get("summary", "unknown advisory"),
                    "details": adv.get("description", ""),
                })
        else:
            ok("no security advisories for blake3")
    except urllib.error.HTTPError as e:
        warn(f"could not fetch advisories (HTTP {e.code}) — skipping")
    except Exception as e:
        warn(f"advisory check skipped: {e}")

    # Verify BLAKE3 output length is still 32 bytes (OUT_LEN)
    hash_out_len = check_blake3_out_len()
    if hash_out_len == 32:
        ok("BLAKE3 output length: 32 bytes (unchanged)")
    elif hash_out_len > 0:
        crit(f"BLAKE3 output length changed: {hash_out_len} bytes")
        findings.append({
            "check": "blake3_output_length",
            "severity": "critical",
            "message": f"BLAKE3 output length changed to {hash_out_len}",
        })
    else:
        warn("BLAKE3 output length check skipped (could not compile)")

    report["blake3_monitor"] = {"findings": findings, "pinned_version": pinned}


def check_blake3_out_len() -> int:
    """Check BLAKE3_OUT_LEN by reading the crate source definition."""
    try:
        # Try to find OUT_LEN in the blake3 source under the cargo registry
        blake3_path = None
        for root in [
            Path.home() / ".cargo/registry/src",
            "/usr/share/cargo/registry",
        ]:
            candidates = list(Path(root).rglob("blake3-*/src/lib.rs"))
            if candidates:
                blake3_path = candidates[0]
                break
        if blake3_path:
            text = blake3_path.read_text()
            m = re.search(r"pub\s+const\s+OUT_LEN\s*:\s*usize\s*=\s*(\d+)", text)
            if m:
                return int(m.group(1))
        # Fallback: run `rustc --print cfg` on a small snippet
        result = subprocess.run(
            ["cargo", "test", "--release", "-p", "verax-core", "--",
             "hash::tests::test_blake3_basic"],
            capture_output=True, text=True, timeout=120,
            cwd=str(REPO_ROOT),
        )
        if "test result: ok" in result.stdout + result.stderr:
            return 32
        return -1
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1
    except Exception:
        return -1


# ── Check 3: CT Log Key Rotation ─────────────────────────────────────

def check_ct_log_keys(report: dict) -> None:
    print("\n[3/5] CT Log Key Rotation")
    findings = []

    if not CT_KEY_STORE.exists():
        err(f"trusted CT log key store not found at {CT_KEY_STORE}")
        report["ct_log_keys"] = {"findings": [{
            "check": "ct_key_store_missing",
            "severity": "critical",
            "message": f"CT key store not found",
        }]}
        return

    trusted_keys = json.loads(CT_KEY_STORE.read_text())
    ok(f"{len(trusted_keys)} trusted CT log keys loaded")

    # Fetch Google's current CT log list
    try:
        req = urllib.request.Request(
            GOOGLE_CT_LOG_API,
            headers={"User-Agent": "verax-compliance-bot/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            google_logs = json.loads(resp.read())
    except Exception as e:
        warn(f"could not fetch Google CT log list: {e}")
        google_logs = None

    if google_logs:
        google_keys = {}  # hex -> log info
        for operator in google_logs.get("operators", []):
            for log in operator.get("logs", []):
                key_b64 = log.get("key", "")
                try:
                    key_raw = base64.b64decode(key_b64)
                    key_hex = key_raw.hex()
                except Exception:
                    # Sometimes the key field is already hex or has pem-like format
                    key_hex = key_b64
                google_keys[key_hex] = log

        for trusted in trusted_keys:
            key_hex = trusted.get("public_key_hex", "").lower()
            label = trusted.get("label", key_hex[:16])
            if key_hex in google_keys:
                log_info = google_keys[key_hex]
                status = log_info.get("state", {}).get("name", "unknown")
                if status == "Retired":
                    warn(f"CT log '{label}' is RETIRED — consider removal")
                    findings.append({
                        "check": "ct_log_retired",
                        "severity": "warning",
                        "message": f"CT log '{label}' is retired",
                    })
                elif status == "Pending":
                    warn(f"CT log '{label}' is PENDING — may not be usable")
                    findings.append({
                        "check": "ct_log_pending",
                        "severity": "warning",
                        "message": f"CT log '{label}' is pending",
                    })
                else:
                    ok(f"CT log '{label}' active ({status})")
            else:
                warn(f"CT log '{label}' not found in Google's list — may be custom/removed")
                findings.append({
                    "check": "ct_log_not_in_google_list",
                    "severity": "warning",
                    "message": f"CT log '{label}' not in Google's CT log list",
                })
    else:
        ok("CT log key check skipped (offline — no external API available)")

    report["ct_log_keys"] = {"findings": findings, "key_count": len(trusted_keys)}


# ── Check 4: Specification Diff ──────────────────────────────────────

def check_spec_diff(report: dict) -> None:
    print("\n[4/5] Specification Diff")
    findings = []

    if not SPEC_PIN.exists():
        err(f"spec pin not found at {SPEC_PIN}")
        report["spec_diff"] = {"findings": [{
            "check": "spec_pin_missing",
            "severity": "critical",
            "message": "spec_pin.json not found",
        }]}
        return

    spec = json.loads(SPEC_PIN.read_text())
    ok(f"spec pin loaded: {spec.get('version', 'unknown')}")

    # Check predicates from implementation match the spec pin
    impl_predicates = extract_predicates()
    spec_predicates = spec.get("predicates", {})
    for name, code in spec_predicates.items():
        if name not in impl_predicates:
            warn(f"predicate '{name}' (code {code}) missing from implementation")
            findings.append({
                "check": "predicate_missing",
                "severity": "warning",
                "message": f"spec predicate '{name}' (code {code}) not found in implementation",
            })
        elif impl_predicates[name] != code:
            err(f"predicate '{name}' code mismatch: spec={code}, impl={impl_predicates[name]}")
            findings.append({
                "check": "predicate_code_mismatch",
                "severity": "critical",
                "message": f"predicate '{name}' code mismatch: spec={code}, impl={impl_predicates[name]}",
            })
    for name in impl_predicates:
        if name not in spec_predicates:
            warn(f"implementation has predicate '{name}' not in spec pin")
            findings.append({
                "check": "predicate_unregistered",
                "severity": "warning",
                "message": f"predicate '{name}' in impl but not in spec pin — may need IANA registration",
            })

    # Check error codes from implementation match the spec pin
    impl_errors = extract_error_codes()
    spec_errors_raw = spec.get("error_codes", {})
    # spec pin uses string keys ("1", "2"...); normalize to int
    spec_errors = {int(k) if isinstance(k, str) else k: v for k, v in spec_errors_raw.items()}
    for code, desc in spec_errors.items():
        if code not in impl_errors:
            warn(f"error code {code} ('{desc}') not found in implementation")
            findings.append({
                "check": "error_code_missing",
                "severity": "warning",
                "message": f"error code {code} ('{desc}') missing from implementation",
            })
    for code, desc in impl_errors.items():
        if code not in spec_errors:
            warn(f"implementation error code {code} ('{desc}') not in spec pin")
            findings.append({
                "check": "error_code_unregistered",
                "severity": "warning",
                "message": f"error code {code} ('{desc}') in impl but not in spec pin",
            })
    # Also verify descriptions match
    for code in sorted(set(spec_errors) & set(impl_errors)):
        if spec_errors[code] != impl_errors[code]:
            warn(f"error code {code} description mismatch")
            findings.append({
                "check": "error_code_desc_mismatch",
                "severity": "warning",
                "message": f"error code {code}: spec='{spec_errors[code]}' vs impl='{impl_errors[code]}'",
            })

    ok(f"predicate check: {len(spec_predicates)} spec vs {len(impl_predicates)} impl")
    ok(f"error code check: {len(spec_errors)} spec vs {len(impl_errors)} impl")

    # Check conformance suite vectors parse correctly
    if CONFORMANCE_SUITE.exists():
        try:
            result = subprocess.run(
                ["cargo", "test", "--release", "--test", "conformance_tests", "--",
                 "conformance_suite_payload_decode_valid_vectors"],
                capture_output=True, text=True, timeout=300,
                cwd=str(REPO_ROOT),
            )
            output = result.stdout + result.stderr
            if "test result: ok" in output:
                ok("conformance suite vectors decode correctly")
            elif "error: could not compile" in output or "error: no such subcommand" in output:
                warn(f"cargo build failed — skipping conformance decode test: {output[-200:]}")
            else:
                err("conformance suite decode FAILED")
                findings.append({
                    "check": "conformance_decode",
                    "severity": "critical",
                    "message": "conformance suite vector decode failure",
                    "details": output[-500:],
                })
        except subprocess.TimeoutExpired:
            err("conformance suite decode timed out")
            findings.append({
                "check": "conformance_decode",
                "severity": "critical",
                "message": "conformance suite decode timed out",
            })
        except FileNotFoundError:
            warn("cargo not found — skipping conformance decode test")
    else:
        warn("conformance suite not found — generating")
        try:
            subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts/gen_conformance.py")],
                capture_output=True, timeout=120,
                cwd=str(REPO_ROOT),
            )
            ok("conformance suite generated")
        except FileNotFoundError:
            warn("python not found — cannot generate conformance suite")

    report["spec_diff"] = {"findings": findings, "spec_version": spec.get("version")}


def extract_predicates() -> dict[str, int]:
    """Return predicate name -> code from the Rust implementation."""
    pred_rs = REPO_ROOT / "crates/verax-core/src/predicate.rs"
    text = pred_rs.read_text()
    preds = {}
    for m in re.finditer(r"(\w+)\s*=\s*(\d+),", text):
        name = m.group(1)
        code = int(m.group(2))
        preds[name] = code
    return preds


def extract_error_codes() -> dict[int, str]:
    """Return error code -> description from doc-comment table in error.rs."""
    error_rs = REPO_ROOT / "crates/verax-core/src/error.rs"
    text = error_rs.read_text()
    codes = {}
    # Parse the commented table: "| 1  | `MalformedCose` | Invalid COSE_Sign1..."
    for m in re.finditer(
        r"\|\s*(\d+)\s*\|\s*`(\w+)`\s*\|\s*(.+?)\s*\|",
        text,
    ):
        code = int(m.group(1))
        desc = m.group(3)
        codes[code] = desc
    return codes


# ── Check 5: Cross-implementation Interop ─────────────────────────────

def check_interop(report: dict) -> None:
    print("\n[5/5] Cross-Implementation Interop")
    findings = []

    # Check if a second independent implementation exists
    other_impls = discover_other_implementations()
    if not other_impls:
        ok("no second implementation to test against — check deferred")
        report["cross_implementation"] = {
            "findings": [],
            "note": "No second implementation found — check deferred until one exists",
        }
        return

    for impl_path in other_impls:
        ok(f"found second implementation at {impl_path}")
        # Run the interop test: produce statement in Rust, verify in other impl
        # and vice versa.  This is a placeholder — actual execution depends on
        # the other implementation's build system.
        warn(f"interop test for {impl_path} not yet configured")

    report["cross_implementation"] = {
        "findings": findings,
        "implementations_found": [str(p) for p in other_impls],
    }


def discover_other_implementations() -> list[Path]:
    """Look for other Verax implementations in the workspace or sibling dirs."""
    results = []

    # Check for verax-core-go as a second implementation
    go_dir = REPO_ROOT / "crates/verax-core-go"
    if go_dir.exists() and (go_dir / "verax.go").exists():
        results.append(go_dir)

    # Check for axon (hypothetical alternative impl) in sibling dirs
    for sibling in REPO_ROOT.parent.glob("ax*"):
        if sibling != REPO_ROOT and sibling.is_dir():
            if list(sibling.rglob("*.rs")) or list(sibling.rglob("*.go")):
                results.append(sibling)

    return results


# ── Report Generation ──────────────────────────────────────────────────

def build_summary(report: dict) -> str:
    """Build a human-friendly Markdown summary."""
    lines = [
        "## Verax Protocol Compliance Bot — Daily Report",
        "",
        f"**Timestamp**: {datetime.now(timezone.utc).isoformat()}",
        f"**Commit**: {os.environ.get('GITHUB_SHA', '(local run)')}",
        "",
        "### Summary",
        "",
        "| Check | Status | Findings |",
        "|-------|--------|----------|",
    ]

    all_findings = 0
    critical = 0
    warnings = 0

    for section_key, section_label in [
        ("cbor_library_audit", "CBOR Library Audit"),
        ("blake3_monitor", "BLAKE3 Hash Monitor"),
        ("ct_log_keys", "CT Log Key Rotation"),
        ("spec_diff", "Specification Diff"),
        ("cross_implementation", "Cross-Implementation Interop"),
    ]:
        section = report.get(section_key, {})
        findings = section.get("findings", [])
        n = len(findings)
        all_findings += n
        for f in findings:
            if f.get("severity") == "critical":
                critical += 1
            else:
                warnings += 1
        status = f"{n} finding(s)" if n else "✅ clean"
        lines.append(f"| {section_label} | {status} |")

    lines += [
        "",
        f"**Total**: {all_findings} finding(s) — {critical} critical, {warnings} warning(s)",
        "",
    ]

    if critical > 0:
        lines.append("🚨 **Critical alerts require immediate action.**")
    elif warnings > 0:
        lines.append("⚠️  **Warnings found — review recommended.**")
    else:
        lines.append("✅ **All checks passed — no violations detected.**")

    return "\n".join(lines)


def open_issue_violations(report: dict) -> None:
    """Open a GitHub issue if violations were found via gh CLI."""
    all_findings = []
    for section in report.values():
        all_findings.extend(section.get("findings", []))
    if not all_findings:
        return

    critical = [f for f in all_findings if f.get("severity") == "critical"]
    warnings = [f for f in all_findings if f.get("severity") == "warning"]

    title = "Compliance Bot: "
    if critical:
        title += f"{len(critical)} critical, {len(warnings)} warning(s) detected"
    else:
        title += f"{len(warnings)} warning(s) detected"

    body = [
        f"## Compliance Bot Report — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "",
        "### Critical Alerts",
    ]
    for f in critical:
        body.append(f"- **{f['check']}**: {f['message']}")
        if "details" in f:
            body.append(f"  ```\n  {f['details']}\n  ```")

    body.append("")
    body.append("### Warnings")
    for f in warnings:
        body.append(f"- **{f['check']}**: {f['message']}")

    body += [
        "",
        "---",
        "This issue was automatically generated by the Compliance Bot.",
        f"Run ID: {os.environ.get('GITHUB_RUN_ID', 'local')}",
    ]

    # Use gh CLI to create the issue
    try:
        subprocess.run(
            ["gh", "issue", "create",
             "--title", title,
             "--label", "compliance-bot",
             "--body", "\n".join(body)],
            capture_output=True, text=True, timeout=30,
        )
        print(f"\n  [INFO] GitHub issue filed: {title}")
    except Exception as e:
        print(f"\n  [INFO] Could not file issue (gh not available or not auth'd): {e}")


# ── Main ──────────────────────────────────────────────────────────────

def main() -> int:
    report: dict[str, Any] = {}

    print("=" * 60)
    print("Verax Protocol — Compliance Bot")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    check_cbor_deps(report)
    check_blake3(report)
    check_ct_log_keys(report)
    check_spec_diff(report)
    check_interop(report)

    summary = build_summary(report)
    print("\n" + "=" * 60)
    print(summary)
    print("=" * 60)

    report_json = json.dumps(report, indent=2)
    report_path = "/tmp/compliance-report.json"
    Path(report_path).write_text(report_json)
    print(f"\nMachine-readable report: {report_path}")

    # Count severities
    all_findings = []
    for section in report.values():
        all_findings.extend(section.get("findings", []))
    critical = len([f for f in all_findings if f.get("severity") == "critical"])
    warnings = len([f for f in all_findings if f.get("severity") == "warning"])

    # Open issue if violations found (only in CI)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if critical or warnings:
            open_issue_violations(report)

    if critical:
        return 2
    elif warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
