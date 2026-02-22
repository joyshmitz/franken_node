# bd-2ja: Compatibility Golden Corpus and Fixture Metadata Schema

**Section:** 10.7 -- Compatibility Testing Infrastructure
**Status:** Implemented
**Artifacts:** `fixtures/conformance/corpus_manifest.json`, `fixtures/conformance/fixture_metadata_schema.json`

## Purpose

Defines a golden corpus of compatibility test fixtures and the JSON Schema that governs fixture metadata. The corpus provides a deterministic, versioned set of API-surface expectations that can be validated across Node.js, Bun, and franken_node runtimes. Each fixture maps a specific API call to its expected behavior, enabling automated compatibility regression detection.

## Fixture Metadata Schema

The schema (`fixture_metadata_schema.json`) follows JSON Schema Draft 2020-12 and enforces the following required fields on every fixture:

| Field | Type | Description |
|-------|------|-------------|
| `fixture_id` | string | Unique identifier matching `^FIX-[A-Z0-9]+-[0-9]+$` |
| `api_surface` | string | The Node.js API being tested (e.g., `fs.readFile`) |
| `band` | enum | Risk/priority band: `core`, `high_value`, `edge`, `unsafe` |
| `expected_behavior` | string | Human-readable description of expected outcome |
| `node_version` | string | Target Node.js version (e.g., `22.x`) |
| `inputs` | object | Input parameters for the test fixture |
| `expected_outputs` | object | Expected output values or types |

Optional fields include `bun_version`, `edge_cases`, `known_divergences`, `spec_section`, and `deterministic`.

## Band Classification

| Band | Purpose | Priority |
|------|---------|----------|
| `core` | Fundamental APIs that must be 100% compatible | Highest |
| `high_value` | Important APIs with significant user impact | High |
| `edge` | Edge cases and error paths | Medium |
| `unsafe` | APIs with known runtime divergences | Lower |

## Corpus Manifest

The corpus manifest (`corpus_manifest.json`) is a versioned collection of fixtures with:

- `schema_version`: Version string for the corpus format (currently `corpus-v1.0`)
- `bead_id`: The bead that produced this corpus (`bd-2ja`)
- `section`: Specification section reference (`10.7`)
- `fixtures`: Array of fixture objects conforming to the metadata schema
- `summary`: Aggregate statistics including total count and band distribution

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-CORPUS-DETERMINISTIC | All fixtures in the golden corpus must be deterministic |
| INV-CORPUS-COMPLETE | Corpus must cover at least `core` and `high_value` bands |
| INV-CORPUS-MINIMUM | At least 8 fixtures must be present |
| INV-CORPUS-VALID | All fixtures must conform to the metadata schema |
| INV-CORPUS-CONSISTENT | Summary statistics must match actual fixture data |
| INV-CORPUS-VERSIONED | Corpus and schema carry version identifiers |

## Gate Behavior

The gate script `scripts/check_compatibility_corpus.py` validates:

1. `fixture_metadata_schema.json` exists and is valid JSON Schema Draft 2020-12
2. `corpus_manifest.json` exists and is valid JSON
3. All fixtures contain every required field
4. All `fixture_id` values match the `^FIX-[A-Z0-9]+-[0-9]+$` pattern
5. All `band` values are in the valid set
6. Band distribution covers at least `core` and `high_value`
7. At least 8 fixtures are present
8. All fixtures have `deterministic: true`
9. Summary section is consistent with actual fixture data

Exit 0 on PASS, exit 1 on FAIL.

## Fixture Coverage (Initial Corpus)

| Fixture ID | API Surface | Band |
|------------|-------------|------|
| FIX-FS-001 | fs.readFile | core |
| FIX-FS-002 | fs.writeFile | core |
| FIX-PROC-001 | process.env | core |
| FIX-NET-001 | net.createServer | high_value |
| FIX-MOD-001 | module.require | core |
| FIX-CLI-001 | process.argv | core |
| FIX-EDGE-001 | fs.readFile (ENOENT) | edge |
| FIX-UNSAFE-001 | vm.runInNewContext | unsafe |

## Known Divergences

| Fixture | Runtime | Description |
|---------|---------|-------------|
| FIX-UNSAFE-001 | bun | vm module has limited support |

## Test Coverage

- Python gate script with `--json` and `--self-test` modes
- Pytest suite covering self-test, valid corpus, missing fields, and invalid bands
