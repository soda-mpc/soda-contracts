#!/bin/bash
KEY=$1
# Run your Python script
while true; do
    echo "Running gen account."
    rm .env
    python3 -m onboardUser.scripts.python.gen_account 
    source .env
    echo "Running transfer native coins."
    python -m onboardUser.scripts.python.transfer_native_coins $KEY Remote
    echo "Running onboard user."
    python3 -m onboardUser.scripts.python.onboard_user Remote 
    source .env
    echo "Running tests"
    python3 -m tests.scripts.python.run_precompile_tests_contract Remote
    python3 -m onboardUser.scripts.python.return_native_coins $KEY Remote
    sleep 300
done