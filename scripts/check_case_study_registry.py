#!/usr/bin/env python3
"""bd-cv49: published security/ops case-study registry verification gate."""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "security_ops_case_studies.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_15", "bd-cv49_contract.md")
TEMPLATE = os.path.join(ROOT, "docs", "templates", "case_study_template.md")
DOC_PAGE = os.path.join(ROOT, "docs", "ecosystem", "migration_case_studies.md")
REGISTRY = os.path.join(ROOT, "artifacts", "15", "case_study_registry.json")

BEAD = "bd-cv49"
SECTION = "15"

CODES = [
    f"CSC-{str(i).zfill(3)}" for i in range(1, 11)
] + ["CSC-ERR-001", "CSC-ERR-002", "CSC-ERR-003"]

INVS = [
    "INV-CSC-PUBLISHED",
    "INV-CSC-MEASURED",
    "INV-CSC-REVIEWED",
    "INV-CSC-DISTRIBUTED",
    "INV-CSC-TEMPLATE",
    "INV-CSC-AUDITABLE",
]


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _load_registry():
    with open(REGISTRY, encoding="utf-8") as handle:
        return json.load(handle)


def _count_security_improvements(case_studies):
    count = 0
    for case_study in case_studies:
        if case_study.get("security_improvement_bps", 0) > 0:
            count += 1
    return count


def _checks():
    results = []

    def add(check, passed, detail=""):
        results.append({"check": check, "passed": passed, "detail": detail})

    add("source_exists", os.path.isfile(IMPL), IMPL)
    if os.path.isfile(IMPL):
        src = _read(IMPL)
    else:
        src = ""

    mod_src = _read(MOD_RS)
    add("module_wiring", "pub mod security_ops_case_studies;" in mod_src)

    for struct_name in (
        "CaseStudy",
        "KeyMetrics",
        "PublicationStatus",
        "CaseStudyRegistrySummary",
        "SecurityOpsCaseStudyRegistry",
    ):
        add(f"struct_{struct_name}", f"struct {struct_name}" in src, struct_name)

    add(
        "event_codes",
        sum(1 for code in CODES if code in src) >= 13,
        f"{sum(1 for code in CODES if code in src)}/13",
    )
    add(
        "invariants",
        sum(1 for inv in INVS if inv in src) >= 6,
        f"{sum(1 for inv in INVS if inv in src)}/6",
    )

    add("spec_alignment", os.path.isfile(SPEC), SPEC)
    add("template_exists", os.path.isfile(TEMPLATE), TEMPLATE)
    add("docs_page_exists", os.path.isfile(DOC_PAGE), DOC_PAGE)

    add("registry_exists", os.path.isfile(REGISTRY), REGISTRY)

    registry = {}
    case_studies = []
    if os.path.isfile(REGISTRY):
        try:
            registry = _load_registry()
            case_studies = registry.get("case_studies", [])
        except json.JSONDecodeError as error:
            add("registry_json_parse", False, str(error))
        else:
            add("registry_json_parse", True, "valid json")
    else:
        add("registry_json_parse", False, "registry missing")

    add(
        "registry_schema_version",
        registry.get("schema_version") == "csc-v1.0",
        str(registry.get("schema_version")),
    )
    add(
        "minimum_case_study_count",
        len(case_studies) >= 3,
        f"{len(case_studies)}/3",
    )

    security_improvement_count = _count_security_improvements(case_studies)
    add(
        "security_improvement_threshold",
        security_improvement_count >= 2,
        f"{security_improvement_count}/2",
    )

    reviewed_count = sum(
        1
        for case_study in case_studies
        if case_study.get("publication_status", {}).get("reviewed_by_featured_org")
    )
    add(
        "review_coverage",
        reviewed_count == len(case_studies) and len(case_studies) > 0,
        f"{reviewed_count}/{len(case_studies)}",
    )

    website_count = sum(
        1
        for case_study in case_studies
        if case_study.get("publication_status", {}).get("published_on_project_website")
    )
    add("website_publication_threshold", website_count >= 3, f"{website_count}/3")

    external_count = sum(
        1
        for case_study in case_studies
        if case_study.get("publication_status", {}).get("submitted_to_industry_publication")
    )
    add("external_submission_threshold", external_count >= 1, f"{external_count}/1")

    required_case_fields = {
        "case_study_id",
        "title",
        "organization_type",
        "key_metrics",
        "publication_status",
        "url",
    }
    all_required_fields = all(
        required_case_fields.issubset(set(case_study.keys())) for case_study in case_studies
    )
    add("required_case_fields", all_required_fields, ", ".join(sorted(required_case_fields)))

    publication_urls_https = all(
        str(case_study.get("url", "")).startswith("https://") for case_study in case_studies
    )
    add("publication_urls_https", publication_urls_https, "all case-study urls must be https")

    summary_verdict = registry.get("summary", {}).get("overall_verdict")
    add("summary_verdict_true", summary_verdict is True, str(summary_verdict))

    rust_test_count = len(re.findall(r"#\[test\]", src))
    add("rust_test_coverage", rust_test_count >= 24, f"{rust_test_count} tests")

    return results


def self_test():
    checks = _checks()
    assert len(checks) >= 20
    for check in checks:
        assert "check" in check and "passed" in check and "detail" in check
    print(f"self_test: {len(checks)} checks OK", file=sys.stderr)
    return True


def main():
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test()
        return

    checks = _checks()
    passed = sum(1 for check in checks if check["passed"])
    total = len(checks)
    verdict = "PASS" if passed == total else "FAIL"

    if as_json:
        print(
            json.dumps(
                {
                    "bead_id": BEAD,
                    "section": SECTION,
                    "gate_script": os.path.basename(__file__),
                    "checks_passed": passed,
                    "checks_total": total,
                    "verdict": verdict,
                    "checks": checks,
                },
                indent=2,
            )
        )
    else:
        for check in checks:
            state = "PASS" if check["passed"] else "FAIL"
            print(f"  [{state}] {check['check']}: {check['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
