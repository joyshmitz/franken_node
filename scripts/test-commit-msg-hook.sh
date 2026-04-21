#!/bin/bash
# Test script for commit-msg security validation hook

set -euo pipefail

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

cd "$test_dir"
git init --quiet

# Copy our hook
hook_script="$(realpath "$1")"
if [ ! -f "$hook_script" ]; then
    echo "❌ ERROR: Hook script not found: $hook_script"
    exit 1
fi

cp "$hook_script" .git/hooks/commit-msg
chmod +x .git/hooks/commit-msg

# Test 1: Security claim with no security files should be rejected
echo "Test 1: Security claim with no security files..."
echo "non-security content" > regular-file.txt
git add regular-file.txt

commit_msg_file=$(mktemp)
echo "security: fix rate limiting vulnerability" > "$commit_msg_file"

if .git/hooks/commit-msg "$commit_msg_file" 2>/dev/null; then
    echo "❌ FAIL: Hook should reject security claim with no security files"
    exit 1
else
    echo "✅ PASS: Hook correctly rejected security claim with no security files"
fi

# Test 2: Security claim with security files should be accepted
echo "Test 2: Security claim with security files..."
mkdir -p crates/franken-node/src/security
echo "security fix content" > crates/franken-node/src/security/auth.rs
git add crates/franken-node/src/security/auth.rs

commit_msg_file2=$(mktemp)
echo "security: fix authentication bypass" > "$commit_msg_file2"

if .git/hooks/commit-msg "$commit_msg_file2" 2>/dev/null; then
    echo "✅ PASS: Hook correctly accepted security claim with security files"
else
    echo "❌ FAIL: Hook should accept security claim with security files"
    exit 1
fi

# Test 3: Non-security commit should be ignored
echo "Test 3: Non-security commit..."
echo "regular change" > another-file.txt
git add another-file.txt

commit_msg_file3=$(mktemp)
echo "feat: add new feature" > "$commit_msg_file3"

if .git/hooks/commit-msg "$commit_msg_file3" 2>/dev/null; then
    echo "✅ PASS: Hook correctly ignored non-security commit"
else
    echo "❌ FAIL: Hook should ignore non-security commits"
    exit 1
fi

echo "🎉 All tests passed!"