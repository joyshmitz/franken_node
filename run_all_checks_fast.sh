#!/bin/bash
export CARGO_TERM_COLOR=always
ls scripts/check_*.py | xargs -n 1 -P 16 -I {} bash -c '
    output=$(python3 "$1" 2>&1)
    status=$?
    if [ $status -ne 0 ]; then
        echo "FAILED: $1"
        echo "$output" > "fail_${1##*/}.log"
    else
        echo "PASSED: $1"
    fi
' _ {}
