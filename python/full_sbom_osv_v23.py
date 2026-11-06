"""F209 bounded official OSV querybatch for 100 real local SBOM components.

One *live* HTTPS POST contains one separately indexed package/version query for
each Cargo.lock crate and each installed verifier wheel. Its saved response is
bound to an exact request, HTTPS source, content digest and pinned snapshot
SHA. Querybatch result ordering is guaranteed by OSV's official specification.

No project/package code is imported. Neither OSV HTTP JSON nor Cargo checksums
establish signed *publisher provenance* for those 100 packages: all are UNKNOWN.
The source code remains read-only in normal `verify` and `capabilities` modes.
Only the explicit `capture` mode contacts the official OSV API and writes one
new snapshot to a private evidence directory.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen


if "supply" not in globals():
    _SUPPLY_SPEC = importlib.util.spec_from_file_location(
        "official_supply_chain_v23", Path(__file__).with_name("official_supply_chain_v23.py"))
    supply = importlib.util.module_from_spec(_SUPPLY_SPEC)
    _SUPPLY_SPEC.loader.exec_module(supply)


OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
SNAPSHOT_FILE = "osv-all100-querybatch.v23.json"
PINNED_SNAPSHOT_SHA256 = "c6888e21999c85b707c1220ce8cd1429629b72135fca461e567df6fae10ba360"
PINNED_WIRE_RESPONSE_SHA256 = "944db654f4a1bde30f0266bfad6de1f77f99d4db288b2d45764262cb91b25686"
PINNED_OFFICIAL_REQUEST_SHA256 = "ea34933851de7f49cf731e5d10bb76d175970ed36a373d379077b332a97e69e4"
# Set only after the operator's final Rust release rebuild. The live OSV
# snapshot remains immutable; pinning a new ELF never rewrites fetched data.
PINNED_FINAL_RELEASE_ELF_SHA256 = "be91fb47aec4f81ee123d5eec4aafe6e81e90a12ba959181f1143ac39f2becb2"
MAX_HTTP_BYTES = 3_000_000
EXPECTED_COMPONENTS = 100


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _components(project, verifier_tools):
    components = supply._sbom(project, verifier_tools)
    if len(components) != EXPECTED_COMPONENTS:
        raise ValueError("sbom_component_count_changed_or_partial")
    names = [(c["ecosystem"], c["name"], c["version"]) for c in components]
    if len(set(names)) != EXPECTED_COMPONENTS:
        raise ValueError("duplicate_sbom_components")
    return components


def _queries(components):
    return [{"package": {"ecosystem": c["ecosystem"], "name": c["name"]},
             "version": c["version"]} for c in components]


def _validate_results(response, expected=EXPECTED_COMPONENTS):
    if type(response) is not dict or type(response.get("results")) is not list:
        raise ValueError("osv_querybatch_response_schema_invalid")
    results = response["results"]
    if len(results) != expected:
        raise ValueError("osv_response_missing_or_extra_component")
    for result in results:
        if type(result) is not dict or result.get("next_page_token"):
            raise ValueError("osv_pagination_or_result_format_not_qualified")
        vulns = result.get("vulns", [])
        if type(vulns) is not list or len(vulns) > 1000:
            raise ValueError("osv_vulnerability_result_budget")
        seen = set()
        for vuln in vulns:
            if (type(vuln) is not dict or
                    not re.fullmatch(r"[A-Za-z0-9-]{6,100}", vuln.get("id", "")) or
                    vuln["id"] in seen):
                raise ValueError("invalid_or_duplicate_osv_vulnerability_id")
            seen.add(vuln["id"])
    return results


def _rust_elf_metadata(project):
    elf = Path(project) / "target" / "release" / "rust-python-healer"
    if elf.is_symlink() or not elf.is_file() or elf.stat().st_size > 30_000_000:
        raise ValueError("real_rust_release_elf_unavailable")
    with elf.open("rb") as file:
        if file.read(4) != b"\x7fELF":
            raise ValueError("rust_executable_is_not_elf")
    return {"path": "target/release/rust-python-healer",
            "sha256": _sha(elf.read_bytes()), "is_elf": True,
            "publisher_provenance_status": "UNKNOWN"}


def active_snapshot_file(evidence_root):
    return (supply.windows_r6_profile(evidence_root)["osv_all100_file"]
            if os.name == "nt" else SNAPSHOT_FILE)


def _verify_windows_r6_snapshot(project, verifier_tools, evidence_root):
    root = supply._private_dir(evidence_root)
    profile = supply.windows_r6_profile(root)
    raw = supply._hashed(root / profile["osv_all100_file"], profile["osv_all100_sha256"], MAX_HTTP_BYTES)
    wire = supply._hashed(root / profile["osv_all100_wire_file"], profile["osv_all100_wire_sha256"], MAX_HTTP_BYTES)
    saved = json.loads(raw)
    components = _components(project, verifier_tools)
    query = {"queries": _queries(components)}
    if (saved.get("schema") != "WINDOWS_R6_OSV_100_COHORT_V1" or
            saved.get("source") != OSV_ENDPOINT or saved.get("response_http_status") != 200 or
            saved.get("transport") != "HTTPS/TLS default CA validation; response unsigned" or
            saved.get("request") != query or saved.get("component_count") != EXPECTED_COMPONENTS or
            saved.get("request_sha256") != profile["osv_all100_request_sha256"] or
            _sha(_json_bytes(query)) != profile["osv_all100_request_sha256"] or
            _sha(supply._read_file(Path(project) / "Cargo.lock", supply.MAX_CARGO_BYTES)) != profile["cargo_lock_sha256"]):
        raise ValueError("forged_osv_source_or_sbom_binding")
    response = saved.get("response")
    results = _validate_results(response)
    if (saved.get("response_wire_sha256") != profile["osv_all100_wire_sha256"] or
            saved.get("response_canonical_sha256") != profile["osv_all100_canonical_response_sha256"] or
            _sha(_json_bytes(response)) != profile["osv_all100_canonical_response_sha256"] or
            json.loads(wire) != response):
        raise ValueError("forged_official_osv_response_content")
    if saved.get("all_component_publishers_authenticated") is not False:
        raise ValueError("unsupported_sbom_publisher_claim")
    if saved.get("osv_response_cryptographically_signed") is not False:
        raise ValueError("false_osv_signature_claim")
    if saved.get("current_R6_release_binary_attested") is not False:
        raise ValueError("unsupported_current_release_binary_claim")
    supply._hashed(root / supply.WHEEL_FILE, profile["artifact_pins"]["wheel"])
    packages = [{"ecosystem": component["ecosystem"], "name": component["name"],
                 "version": component["version"], "official_osv_query_executed": True,
                 "advisory_ids": [v["id"] for v in result.get("vulns", [])],
                 "advisory_count": len(result.get("vulns", [])),
                 "publisher_provenance_status": "UNKNOWN"}
                for component, result in zip(components, results)]
    return {"status": "OFFICIAL_OSV_100_WINDOWS_R6_COHORT_VERIFIED_RELEASE_HOLD",
            "profile_id": profile["profile_id"], "evidence_scope": "WINDOWS_R6_NEW_DATED_OSV",
            "querybatch_source": OSV_ENDPOINT, "component_count": len(packages),
            "content_addressed_snapshot_sha256": profile["osv_all100_sha256"],
            "advisory_findings": sum(item["advisory_count"] for item in packages),
            "packages": packages, "pypi_wheel_sha256": profile["artifact_pins"]["wheel"],
            "current_R6_release_binary_attested": False, "legacy_v23_snapshot_replayed": False,
            "legacy_snapshot_replay_status": profile["legacy_snapshot_replay_status"],
            "signed_publisher_provenance_of_all_packages_proven": False,
            "osv_snapshot_does_not_prove_absence_of_unknown_vulnerabilities": True,
            "osv_response_cryptographically_signed": False,
            "project_package_code_executed": False, "full_product_safety_proven": False}


def capture_live(project, verifier_tools, evidence_root):
    """Explicit one-off official HTTPS query; no arbitrary URL is accepted."""
    root = supply._private_dir(evidence_root)
    destination = root / active_snapshot_file(root)
    if destination.exists() or destination.is_symlink():
        raise ValueError("snapshot_already_exists_no_overwrite")
    if os.name == "nt":
        raise ValueError("windows_r6_capture_requires_new_explicit_dated_receipt")
    components = _components(project, verifier_tools)
    query = {"queries": _queries(components)}
    request_bytes = _json_bytes(query)
    request = Request(OSV_ENDPOINT, data=request_bytes,
                      headers={"Content-Type": "application/json", "Accept": "application/json"},
                      method="POST")
    try:
        with urlopen(request, timeout=55) as received:
            if received.status != 200 or received.url != OSV_ENDPOINT:
                raise ValueError("not_from_official_osv_api")
            response_bytes = received.read(MAX_HTTP_BYTES + 1)
            etag = received.headers.get("ETag")
            content_type = received.headers.get("Content-Type", "")
    except (TimeoutError, OSError) as exc:
        raise ValueError("official_osv_https_query_failed") from exc
    if (len(response_bytes) > MAX_HTTP_BYTES or
            "application/json" not in content_type):
        raise ValueError("osv_http_payload_budget_or_type")
    response = json.loads(response_bytes)
    results = _validate_results(response)
    record = {"version": 1, "source": OSV_ENDPOINT,
              "captured_utc": datetime.now(timezone.utc).isoformat(),
              "transport": "HTTPS/TLS certificate validation by Python default CA context",
              "response_http_status": 200,
              "response_etag": etag,
              "request_sha256": _sha(request_bytes),
              "response_sha256": _sha(response_bytes),
              "request": query, "response": response,
              "component_count": len(results),
              "binary_elf": _rust_elf_metadata(project),
              "official_wheel_sha256": supply.PINNED["wheel"],
              "publisher_provenance_of_sbom_components": "UNKNOWN",
              "cryptographically_signed_osv_response": False}
    # Writing only the explicit filename, and only once, preserves the signed
    # verifier evidence, Cargo.lock and all user files unchanged.
    destination.write_bytes(_json_bytes(record))
    return {"status": "LIVE_OFFICIAL_OSV_100_QUERIES_SNAPSHOT_CAPTURED",
            "snapshot_sha256": _sha(destination.read_bytes()),
            "component_count": len(results),
            "advisory_findings": sum(len(r.get("vulns", [])) for r in results),
            "querybatch_source": OSV_ENDPOINT}


def verify_offline_snapshot(project, verifier_tools, evidence_root):
    if os.name == "nt":
        return _verify_windows_r6_snapshot(project, verifier_tools, evidence_root)
    if not re.fullmatch(r"[0-9a-f]{64}", PINNED_SNAPSHOT_SHA256):
        raise ValueError("snapshot_sha256_not_yet_pinned")
    root = supply._private_dir(evidence_root)
    raw = supply._hashed(root / SNAPSHOT_FILE, PINNED_SNAPSHOT_SHA256,
                         limit=MAX_HTTP_BYTES)
    saved = json.loads(raw)
    components = _components(project, verifier_tools)
    canonical_request = {"queries": _queries(components)}
    if (saved.get("source") != OSV_ENDPOINT or
            saved.get("transport") != "HTTPS/TLS certificate validation by Python default CA context" or
            saved.get("response_http_status") != 200 or
            saved.get("request") != canonical_request or
            saved.get("request_sha256") != PINNED_OFFICIAL_REQUEST_SHA256 or
            saved.get("request_sha256") != _sha(_json_bytes(canonical_request)) or
            saved.get("component_count") != EXPECTED_COMPONENTS):
        raise ValueError("forged_osv_source_or_sbom_binding")
    response = saved.get("response")
    _validate_results(response)
    # In this captured response the wire bytes were *already* canonical JSON,
    # so the independently pinned wire SHA also matches their parsed contents.
    # A forged feed therefore cannot pass by merely updating a local receipt.
    if (saved.get("response_sha256") != PINNED_WIRE_RESPONSE_SHA256 or
            _sha(_json_bytes(response)) != PINNED_WIRE_RESPONSE_SHA256):
        raise ValueError("forged_official_osv_response_content")
    if saved.get("publisher_provenance_of_sbom_components") != "UNKNOWN":
        raise ValueError("unsupported_sbom_publisher_claim")
    if saved.get("cryptographically_signed_osv_response") is not False:
        raise ValueError("false_osv_signature_claim")
    source_elf = _rust_elf_metadata(project)
    wheel = supply._hashed(root / supply.WHEEL_FILE, supply.PINNED["wheel"])
    if len(wheel) == 0:
        raise ValueError("empty_pinned_wheel")
    responses = response["results"]
    per_package = []
    for component, result in zip(components, responses):
        per_package.append({"ecosystem": component["ecosystem"],
                            "name": component["name"], "version": component["version"],
                            "official_osv_query_executed": True,
                            "advisory_ids": [v["id"] for v in result.get("vulns", [])],
                            "advisory_count": len(result.get("vulns", [])),
                            "publisher_provenance_status": "UNKNOWN"})
    elf_matches_capture = source_elf["sha256"] == saved["binary_elf"]["sha256"]
    elf_matches_final = (PINNED_FINAL_RELEASE_ELF_SHA256 is not None and
                         source_elf["sha256"] == PINNED_FINAL_RELEASE_ELF_SHA256)
    elf_qualified = (elf_matches_capture if PINNED_FINAL_RELEASE_ELF_SHA256 is None
                     else elf_matches_final)
    return {"status": ("OFFICIAL_OSV_100_OF_100_COMPONENTS_QUERIED_OFFLINE_AUDITED"
                       if elf_qualified else
                       "OFFICIAL_OSV_100_QUERIES_STALE_RUST_ELF_PARTIAL"),
            "querybatch_source": OSV_ENDPOINT,
            "content_addressed_snapshot_sha256": PINNED_SNAPSHOT_SHA256,
            "querybatch_etag_if_provided": saved.get("response_etag"),
            "component_count": len(per_package),
            "advisory_findings": sum(item["advisory_count"] for item in per_package),
            "packages": per_package,
            "rust_elf": source_elf,
            "same_rust_elf_as_capture": elf_matches_capture,
            "final_release_elf_pin_present": PINNED_FINAL_RELEASE_ELF_SHA256 is not None,
            "matches_pinned_final_release_elf": elf_matches_final,
            "pypi_wheel_sha256": supply.PINNED["wheel"],
            "signed_publisher_provenance_of_all_packages_proven": False,
            "osv_snapshot_does_not_prove_absence_of_unknown_vulnerabilities": True,
            "project_package_code_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "verify", "capture"),
                        default="capabilities")
    parser.add_argument("--project")
    parser.add_argument("--tool-root")
    parser.add_argument("--evidence")
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            result = {"status": "OFFICIAL_OSV_FULL_SBOM_ADAPTER_AVAILABLE",
                      "network_performed": False, "user_code_executed": False}
        elif args.mode == "capture":
            result = capture_live(args.project, args.tool_root, args.evidence)
        else:
            result = verify_offline_snapshot(args.project, args.tool_root, args.evidence)
    except (ValueError, TypeError, OSError, RuntimeError, UnicodeError):
        result = {"status": "REFUSED_OFFICIAL_OSV_SBOM_EVIDENCE",
                  "all_components_qualified": False, "user_code_executed": False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 2 if result["status"].startswith("REFUSED") else 0


if __name__ == "__main__":
    raise SystemExit(main())
