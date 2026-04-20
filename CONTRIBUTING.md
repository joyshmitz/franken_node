# Contributing to Franken Node

## Security Testing

### Golden Artifacts Testing

The project uses golden artifacts testing to ensure deterministic outputs for critical security components. Golden files capture expected outputs for trust cards, registry operations, and claim processing.

#### Updating Golden Files

When security logic changes, you may need to update golden files:

```bash
# Create or update all golden files
UPDATE_GOLDENS=1 cargo test golden_artifacts_comprehensive

# Review the changes
git diff tests/golden/

# Commit the updated golden files
git add tests/golden/
git commit -m "update: golden artifacts for security changes"
```

#### Golden Test Coverage

Golden tests cover:
- Trust card JSON exports and human-readable formats
- Registry receipts and verification reports  
- Claim envelope structures and gate results
- All outputs use scrubbing for timestamps, UUIDs, and paths

#### CI Integration

The CI workflow validates:
- Golden files match expected outputs (fails on mismatch)
- No golden files are auto-generated during CI
- Golden files must be committed in advance

### Security Fuzzing

The security domain includes comprehensive structure-aware fuzzing:

#### Fuzz Targets

```bash
cd fuzz

# Run individual fuzz targets
cargo fuzz run fuzz_constant_time_comparison
cargo fuzz run fuzz_threshold_signature_verification  
cargo fuzz run fuzz_epoch_key_derivation
cargo fuzz run fuzz_intent_firewall
cargo fuzz run fuzz_ssrf_policy
```

#### Fuzz Target Coverage

- **Constant-time operations**: Timing attack prevention (ct_eq, ct_eq_bytes)
- **Threshold signatures**: Ed25519 k-of-n verification with attack vectors
- **Epoch-scoped keys**: HKDF key derivation with domain separation
- **Intent firewall**: Remote effect classification and traffic policy
- **SSRF policy**: Server-side request forgery prevention and IPv4 parsing

#### Debugging Crashes

If fuzzing finds crashes:

```bash
# Minimize crash input
cargo fuzz tmin <target> artifacts/<target>/crash-<hash>

# Add regression test
# Edit crates/franken-node/src/security/fuzz_regression_tests.rs
```

### Security Hardening Patterns

All security code follows hardening patterns:
- `ct_eq()` for constant-time comparisons (timing attack prevention)
- `saturating_add()` for arithmetic (overflow prevention) 
- Fail-closed semantics (`>=` for expiry checks)
- Domain separators in hash inputs
- Length validation and bounded collections

### Running Tests

```bash
# Full security test suite
cargo test -- security::

# Golden artifacts only  
cargo test golden_artifacts_comprehensive

# Security regression tests
cargo test -- security::fuzz_regression

# Validate fuzz targets compile
cd fuzz && cargo check --bins
```

### CI Workflows

Security changes trigger:
- **Golden artifacts validation**: Ensures deterministic outputs
- **Fuzzing validation**: Compiles targets and runs short campaigns  
- **Integration testing**: Full security module test suite
- **Pattern validation**: Checks for required hardening patterns

For questions about security testing, see the fuzzing targets in `fuzz/fuzz_targets/` and regression tests in `crates/franken-node/src/security/fuzz_regression_tests.rs`.