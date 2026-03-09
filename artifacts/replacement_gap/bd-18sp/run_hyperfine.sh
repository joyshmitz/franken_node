#!/usr/bin/env bash
set -euo pipefail

hyperfine \
  --warmup 3 \
  --runs 10 \
  --export-json artifacts/replacement_gap/bd-18sp/hyperfine_supervision_kernel.json \
  --command-name reference \
  "env CARGO_TARGET_DIR=/tmp/rch_target_bd18sp_hyperfine cargo test --manifest-path artifacts/replacement_gap/bd-18sp/supervision_kernel_harness/Cargo.toml supervision::tests::benchmark_reference_restart_budget_kernel --lib --release -- --ignored --exact --nocapture" \
  --command-name monotone-queue \
  "env CARGO_TARGET_DIR=/tmp/rch_target_bd18sp_hyperfine cargo test --manifest-path artifacts/replacement_gap/bd-18sp/supervision_kernel_harness/Cargo.toml supervision::tests::benchmark_monotone_queue_restart_budget_kernel --lib --release -- --ignored --exact --nocapture"
