# franken_node External Reproduction Playbook

This playbook enables any competent engineer to independently reproduce
franken_node's headline claims using only publicly available tools and
fixtures. No insider knowledge or access to internal CI systems is required.

## 1. Environment Setup

### 1.1 Operating System

| Platform | Minimum Version |
|----------|----------------|
| Linux x86_64 | Ubuntu 22.04 / Fedora 38 / Debian 12 |
| macOS ARM64 | macOS 14.0 (Sonoma) |

### 1.2 Toolchain Installation

Install the following tools with the exact pinned versions:

| Tool | Version | Install Command |
|------|---------|-----------------|
| Rust (nightly) | `1.82.0-nightly` | `rustup install nightly-2026-02-15 && rustup default nightly-2026-02-15` |
| Node.js | `v22.3.0` | `nvm install 22.3.0 && nvm use 22.3.0` |
| Python | `3.11+` | System package or `pyenv install 3.11.9` |
| Cargo | `1.82.0-nightly` | Installed with Rust toolchain |

### 1.3 System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential pkg-config libssl-dev

# Fedora
sudo dnf install -y gcc gcc-c++ openssl-devel

# macOS
xcode-select --install
brew install openssl@3
```

### 1.4 Resource Requirements

| Resource | Minimum |
|----------|---------|
| CPU cores | 4 |
| RAM | 8 GB |
| Disk space | 10 GB |
| Network | Required for initial setup; offline after fixtures are downloaded |

### 1.5 Clone and Prepare

```bash
git clone https://github.com/nicholasgasior/franken_node.git
cd franken_node
```

## 2. Fixture Download

### 2.1 Fixture Location

Test fixtures are stored in the repository under `tests/fixtures/`. For large
fixtures that are not checked in, use the generation scripts:

```bash
python3 scripts/generate_fixtures.py
```

### 2.2 Fixture Checksums

After downloading or generating fixtures, verify their integrity:

```bash
python3 scripts/verify_fixture_checksums.py
```

Expected checksums are recorded in `tests/fixtures/checksums.sha256`.

### 2.3 Fixture Generation Fallback

If network access is unavailable, all fixtures can be generated locally from
deterministic seeds:

```bash
python3 scripts/generate_fixtures.py --offline --seed=franken_node_v1
```

The generated fixtures produce byte-identical outputs regardless of platform.

## 3. Benchmark Execution

### 3.1 Running All Verification Suites

The automation script handles everything:

```bash
python3 scripts/reproduce.py --skip-install
```

### 3.2 Individual Claim Verification

To verify a specific headline claim:

```bash
python3 scripts/reproduce.py --claim HC-001
```

### 3.3 Expected Duration

| Suite | Approximate Duration |
|-------|---------------------|
| Compatibility tests | 5-15 minutes |
| Security verification | 2-5 minutes |
| Performance benchmarks | 10-30 minutes |
| Full reproduction | 20-60 minutes |

Duration varies by hardware. The automation script reports actual wall-clock
time for each phase.

### 3.4 Resource Usage During Execution

- Peak memory: ~4 GB during compilation, ~2 GB during test execution.
- CPU: All available cores used during compilation; benchmarks use controlled
  core counts for reproducibility.

## 4. Result Comparison

### 4.1 Pass/Fail Criteria

Each headline claim has a defined acceptance threshold in
`docs/headline_claims.toml`. A claim passes if the measured value meets or
exceeds the threshold.

### 4.2 Acceptable Variance

| Claim Type | Acceptable Variance |
|------------|-------------------|
| Compatibility (pass rate) | 0% (must be exact) |
| Security (pass rate) | 0% (must be exact) |
| Performance (latency) | +/- 10% of reference value |
| Performance (throughput) | +/- 10% of reference value |

### 4.3 Report Interpretation

The reproduction report (`reproduction_report.json`) contains:

```json
{
  "environment": { "os": "...", "cpu": "...", "memory_gb": 64, "rust_version": "...", "node_version": "...", "python_version": "..." },
  "claims": [
    { "claim_id": "HC-001", "measured_value": "100%", "threshold": "100%", "pass": true }
  ],
  "verdict": "PASS",
  "timestamp": "2026-02-20T12:00:00Z",
  "duration_seconds": 1234
}
```

- `verdict`: PASS if all claims pass; FAIL if any claim fails.
- `claims`: Per-claim breakdown with measured vs. threshold values.
- `environment`: Full fingerprint for traceability.

### 4.4 Sharing Results

Send the `reproduction_report.json` to the franken_node team for inclusion in
the external reproduction evidence log.

## 5. Troubleshooting

### 5.1 Rust Nightly Not Found

If the pinned nightly version is unavailable:

```bash
rustup install nightly
rustup default nightly
```

Note: Using a different nightly may produce minor differences in compiler
output. Record the actual version in your reproduction report.

### 5.2 Node.js Version Mismatch

The `nvm` tool manages multiple Node.js versions:

```bash
nvm install 22.3.0
nvm use 22.3.0
node --version  # Should print v22.3.0
```

### 5.3 OpenSSL Linking Errors

On macOS with Homebrew OpenSSL:

```bash
export OPENSSL_DIR=$(brew --prefix openssl@3)
export PKG_CONFIG_PATH="$OPENSSL_DIR/lib/pkgconfig"
```

### 5.4 Insufficient Memory

If compilation fails with OOM:

```bash
# Reduce parallel jobs
cargo build --jobs 2
```

Or increase swap space.

### 5.5 Platform-Specific Test Failures

Some tests exercise platform-specific behavior. Known platform differences are
documented in the divergence ledger (`docs/divergence_ledger.md`). If a test
fails only on your platform, check the ledger before filing a bug.

### 5.6 Fixture Checksum Mismatch

If fixture checksums do not match after download, regenerate from seed:

```bash
python3 scripts/generate_fixtures.py --offline --seed=franken_node_v1 --force
```

If regeneration also fails, file an issue with your environment fingerprint.

### 5.7 Benchmark Variance Exceeds Threshold

Performance benchmarks are sensitive to system load. For best results:

- Close other applications.
- Disable CPU frequency scaling if possible.
- Run benchmarks multiple times and take the median.

```bash
python3 scripts/reproduce.py --claim HC-003 --iterations 5
```
