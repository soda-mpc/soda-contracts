#!/bin/bash

# Check if MASTER_KEY is not empty
if [ -z "$MASTER_KEY" ]; then
  echo "Error: MASTER_KEY is empty. Please set the MASTER_KEY environment variable."
  exit 1
fi

if [ -z "$RPC_NODE_URL" ]; then
  echo "Error: RPC_NODE_URL is empty. Please set the RPC_NODE_URL environment variable."
  exit 1
fi


# Run the scripts
python3 -m onboardUser.scripts.python.gen_account $RPC_NODE_URL
source .env
python3 -m onboardUser.scripts.python.transfer_native_coins $MASTER_KEY $RPC_NODE_URL
python3 -m onboardUser.scripts.python.onboard_user $RPC_NODE_URL
source .env

# Run the tests in a loop
while true; do
  python3 -m tests.scripts.python.run_precompile_tests_contract $RPC_NODE_URL
done
