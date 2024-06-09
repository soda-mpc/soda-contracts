#!/bin/bash

for i in {1..1000}; do
    echo "Running test $i"
    python3 -m tests.scripts.python.run_precompile_tests_contract Local
done