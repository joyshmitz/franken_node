#!/usr/bin/env python3
"""Validate sqlmodel_rust usage policy coverage and ownership integrity (bd-bt82)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

POLICY_DOC_PATH = ROOT / "docs" / "specs" / "sqlmodel_rust_usage_policy.md"
POLICY_MATRIX_PATH = ROOT / "artifacts" / "10.16" / "sqlmodel_policy_matrix.json"
PERSISTENCE_MATRIX_PATH = ROOT / "artifacts" / "10.16" / "frankensqlite_persistence_matrix.json"

REQUIRED_DOC_SECTIONS = [
    "## Classification Policy",
    "## Model Ownership Rules",
    "## Codegen and Versioning Expectations",
    "## Schema Drift Detection",
    "## Boundary with frankensqlite",
    "## Event Codes",
]

REQUIRED_EVENT_CODES = {
    "SQLMODEL_POLICY_LOADED",
    "SQLMODEL_DOMAIN_UNCLASSIFIED",
    "SQLMODEL_OWNERSHIP_CONFLICT",
    "SQLMODEL_CODEGEN_STALE",
}

REQUIRED_DOMAIN_KEYS = {
    "name",
    "owner_module",
    "classification",
    "model_source",
    "version",
    "model_name",
    "typed_model_defined",
}

ALLOWED_CLASSIFICATIONS = {"mandatory", "should_use", "optional"}
ALLOWED_MODEL_SOURCES = {"hand_authored", "codegen"}
ALLOWED_CHECKLIST_STATUS = {"defined", "pending", "waived"}
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def _rel(path: Path, base: Path = ROOT) -> str:
    try:
        return _norm(path.relative_to(base))
    except ValueError:
        return _norm(path)


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_persistence_domains(source_matrix_path: Path) -> set[str]:
    if not source_matrix_path.is_file():
        raise FileNotFoundError(f"missing source persistence matrix: {source_matrix_path}")
    source = json.loads(source_matrix_path.read_text(encoding="utf-8"))
    classes = source.get("persistence_classes", [])
    if not isinstance(classes, list):
        raise ValueError("source persistence matrix persistence_classes must be a list")
    domains = set()
    for item in classes:
        if isinstance(item, dict):
            name = item.get("domain")
            if isinstance(name, str) and name:
                domains.add(name)
    return domains


def evaluate_policy(
    policy_matrix: dict[str, Any],
    policy_doc_text: str,
    expected_domains: set[str],
) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    trace = _trace_id(policy_matrix)
    events.append(
        {
            "event_code": "SQLMODEL_POLICY_LOADED",
            "severity": "info",
            "trace_correlation": trace,
            "message": "Loaded sqlmodel policy matrix.",
        }
    )

    for section in REQUIRED_DOC_SECTIONS:
        if section not in policy_doc_text:
            errors.append(f"policy doc missing section: {section}")

    event_codes = set(policy_matrix.get("event_codes", []))
    missing_event_codes = sorted(REQUIRED_EVENT_CODES - event_codes)
    if missing_event_codes:
        errors.append(f"missing required event codes: {', '.join(missing_event_codes)}")

    checklist = policy_matrix.get("checklist")
    if not isinstance(checklist, list) or not checklist:
        errors.append("checklist must be a non-empty list")
    else:
        pending = []
        for idx, item in enumerate(checklist):
            if not isinstance(item, dict):
                errors.append(f"checklist[{idx}] must be an object")
                continue
            status = item.get("status")
            if status not in ALLOWED_CHECKLIST_STATUS:
                errors.append(f"checklist[{idx}] has invalid status `{status}`")
                continue
            if status == "pending":
                pending.append(item.get("requirement", f"item_{idx}"))
        if pending:
            errors.append(f"pending checklist requirements: {', '.join(pending)}")

    domains = policy_matrix.get("domains")
    if not isinstance(domains, list) or not domains:
        errors.append("domains must be a non-empty list")
        domains = []

    ownership_rules = policy_matrix.get("ownership_rules")
    if not isinstance(ownership_rules, dict):
        errors.append("ownership_rules must be an object")
        ownership_rules = {}

    module_to_models = ownership_rules.get("module_to_models", {})
    model_to_module = ownership_rules.get("model_to_module", {})

    if not isinstance(module_to_models, dict):
        errors.append("ownership_rules.module_to_models must be an object")
        module_to_models = {}
    if not isinstance(model_to_module, dict):
        errors.append("ownership_rules.model_to_module must be an object")
        model_to_module = {}

    codegen_config = policy_matrix.get("codegen_config")
    if not isinstance(codegen_config, dict):
        errors.append("codegen_config must be an object")
    else:
        for key in ("generation_strategy", "schema_source"):
            if not isinstance(codegen_config.get(key), str) or not codegen_config.get(key):
                errors.append(f"codegen_config.{key} must be a non-empty string")
        if not isinstance(codegen_config.get("generated_artifacts"), list):
            errors.append("codegen_config.generated_artifacts must be a list")
        stale = codegen_config.get("stale_model_policy")
        if not isinstance(stale, dict):
            errors.append("codegen_config.stale_model_policy must be an object")

    seen_domains: set[str] = set()
    seen_models: dict[str, str] = {}

    for idx, domain in enumerate(domains):
        if not isinstance(domain, dict):
            errors.append(f"domains[{idx}] must be an object")
            continue

        missing = sorted(REQUIRED_DOMAIN_KEYS - set(domain.keys()))
        if missing:
            errors.append(f"domains[{idx}] missing keys: {', '.join(missing)}")
            continue

        name = domain.get("name")
        owner_module = domain.get("owner_module")
        classification = domain.get("classification")
        model_source = domain.get("model_source")
        version = domain.get("version")
        model_name = domain.get("model_name")
        typed_model_defined = domain.get("typed_model_defined")

        if not isinstance(name, str) or not name:
            errors.append(f"domains[{idx}].name must be a non-empty string")
            continue
        seen_domains.add(name)

        if not isinstance(owner_module, str) or not owner_module:
            errors.append(f"{name}: owner_module must be a non-empty string")

        if classification not in ALLOWED_CLASSIFICATIONS:
            errors.append(f"{name}: invalid classification `{classification}`")

        if model_source not in ALLOWED_MODEL_SOURCES:
            errors.append(f"{name}: invalid model_source `{model_source}`")

        if not isinstance(version, str) or not SEMVER_RE.match(version):
            errors.append(f"{name}: version must be semver (x.y.z)")

        if not isinstance(typed_model_defined, bool):
            errors.append(f"{name}: typed_model_defined must be boolean")

        if classification == "mandatory":
            if typed_model_defined is not True:
                errors.append(f"{name}: mandatory domain must set typed_model_defined=true")
            if not isinstance(model_name, str) or not model_name:
                errors.append(f"{name}: mandatory domain requires non-empty model_name")

        if isinstance(model_name, str) and model_name:
            prior = seen_models.get(model_name)
            if prior is not None and prior != owner_module:
                message = (
                    f"model ownership conflict for `{model_name}`: {prior} vs {owner_module}"
                )
                errors.append(message)
                events.append(
                    {
                        "event_code": "SQLMODEL_OWNERSHIP_CONFLICT",
                        "severity": "error",
                        "trace_correlation": trace,
                        "model": model_name,
                        "message": message,
                    }
                )
            else:
                seen_models[model_name] = owner_module

            mapped_owner = model_to_module.get(model_name)
            if mapped_owner != owner_module:
                errors.append(
                    f"model_to_module mismatch for `{model_name}`: expected {owner_module}, got {mapped_owner}"
                )

            module_models = module_to_models.get(owner_module, [])
            if not isinstance(module_models, list) or model_name not in module_models:
                errors.append(
                    f"module_to_models missing `{model_name}` under owner `{owner_module}`"
                )

        # Codegen freshness warning channel.
        if model_source == "codegen" and isinstance(version, str) and version.startswith("0."):
            warning = f"{name}: codegen model version `{version}` may be stale"
            warnings.append(warning)
            events.append(
                {
                    "event_code": "SQLMODEL_CODEGEN_STALE",
                    "severity": "warning",
                    "trace_correlation": trace,
                    "domain": name,
                    "message": warning,
                }
            )

    missing_domains = sorted(expected_domains - seen_domains)
    for domain_name in missing_domains:
        message = f"persistence domain missing sqlmodel classification: {domain_name}"
        errors.append(message)
        events.append(
            {
                "event_code": "SQLMODEL_DOMAIN_UNCLASSIFIED",
                "severity": "error",
                "trace_correlation": trace,
                "domain": domain_name,
                "message": message,
            }
        )

    success = len(errors) == 0
    report = {
        "ok": success,
        "trace_correlation": trace,
        "expected_domain_count": len(expected_domains),
        "classified_domain_count": len(seen_domains),
        "missing_domains": missing_domains,
        "model_count": len(seen_models),
        "errors": errors,
        "warnings": warnings,
        "events": events,
    }
    return success, report


def run_checks(
    policy_matrix_path: Path = POLICY_MATRIX_PATH,
    policy_doc_path: Path = POLICY_DOC_PATH,
    source_persistence_matrix_path: Path = PERSISTENCE_MATRIX_PATH,
) -> tuple[bool, dict[str, Any]]:
    if not policy_matrix_path.is_file():
        raise FileNotFoundError(f"missing sqlmodel policy matrix: {policy_matrix_path}")
    if not policy_doc_path.is_file():
        raise FileNotFoundError(f"missing sqlmodel policy doc: {policy_doc_path}")

    policy_matrix = json.loads(policy_matrix_path.read_text(encoding="utf-8"))
    policy_doc_text = policy_doc_path.read_text(encoding="utf-8")
    expected_domains = _load_persistence_domains(source_persistence_matrix_path)

    ok, report = evaluate_policy(policy_matrix, policy_doc_text, expected_domains)
    result = {
        "bead_id": "bd-bt82",
        "policy_doc": _rel(policy_doc_path),
        "policy_matrix": _rel(policy_matrix_path),
        "source_persistence_matrix": _rel(source_persistence_matrix_path),
        **report,
    }
    return ok, result


def self_test() -> tuple[bool, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="sqlmodel-policy-selftest-") as tmp:
        root = Path(tmp)

        policy_doc = root / "policy.md"
        policy_doc.write_text("\n".join(REQUIRED_DOC_SECTIONS), encoding="utf-8")

        source_matrix = root / "persistence.json"
        source_matrix.write_text(
            json.dumps(
                {
                    "persistence_classes": [
                        {"domain": "domain_a"},
                        {"domain": "domain_b"},
                    ]
                }
            ),
            encoding="utf-8",
        )

        policy = {
            "event_codes": sorted(REQUIRED_EVENT_CODES),
            "checklist": [{"requirement": "complete", "status": "defined"}],
            "domains": [
                {
                    "name": "domain_a",
                    "owner_module": "a.rs",
                    "classification": "mandatory",
                    "model_source": "hand_authored",
                    "version": "1.0.0",
                    "model_name": "DomainA",
                    "typed_model_defined": True,
                },
                {
                    "name": "domain_b",
                    "owner_module": "b.rs",
                    "classification": "optional",
                    "model_source": "codegen",
                    "version": "1.1.0",
                    "model_name": "DomainB",
                    "typed_model_defined": True,
                },
            ],
            "ownership_rules": {
                "module_to_models": {"a.rs": ["DomainA"], "b.rs": ["DomainB"]},
                "model_to_module": {"DomainA": "a.rs", "DomainB": "b.rs"},
            },
            "codegen_config": {
                "generation_strategy": "hybrid",
                "schema_source": "schema",
                "generated_artifacts": ["rows"],
                "stale_model_policy": {"warning_event": "SQLMODEL_CODEGEN_STALE"},
            },
        }

        ok, report = evaluate_policy(
            policy,
            policy_doc.read_text(encoding="utf-8"),
            _load_persistence_domains(source_matrix),
        )
        assert ok, f"self_test expected pass but got errors: {report['errors']}"

        # Integration behavior: new persistence domain should fail if unclassified.
        source_matrix.write_text(
            json.dumps(
                {
                    "persistence_classes": [
                        {"domain": "domain_a"},
                        {"domain": "domain_b"},
                        {"domain": "domain_c"},
                    ]
                }
            ),
            encoding="utf-8",
        )

        ok_missing, report_missing = evaluate_policy(
            policy,
            policy_doc.read_text(encoding="utf-8"),
            _load_persistence_domains(source_matrix),
        )
        assert not ok_missing
        assert any("missing sqlmodel classification" in e for e in report_missing["errors"])

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
    logger = configure_test_logging("check_sqlmodel_policy")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="run internal self-test")
    args = parser.parse_args()

    try:
        if args.self_test:
            ok, payload = self_test()
        else:
            ok, payload = run_checks()
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        payload = {"ok": False, "error": str(exc)}
        ok = False

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if ok:
            print("PASS")
        else:
            print("FAIL")
            for err in payload.get("errors", [payload.get("error", "unknown error")]):
                print(f"- {err}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
