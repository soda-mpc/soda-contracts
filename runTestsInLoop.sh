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

# Load Slack token and channel ID
TOKEN=$SLACK_TOKEN
CHANNEL=$ALERTS_CHANNEL_ID
ENV_NAME=$ENV_NAME


# Send the message
send_slack_notification() {
  local message="$1"  # The message to send
  MESSAGE_PAYLOAD="[$ENV_NAME] $message"  # Prefix message with the environment name
  echo "Sending message to Slack channel: $MESSAGE_PAYLOAD"
  curl -X POST -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-type: application/json" \
      --data "{\"channel\":\"${CHANNEL}\",\"text\":\"${MESSAGE_PAYLOAD}\"}" \
      https://slack.com/api/chat.postMessage
}

# Message text
send_slack_notification "Starting MPC tests"

last_notification_time=$(date +%s)  # Current timestamp in seconds

output_file="mpc_tests_output_$(date +%Y-%m-%d_%H-%M-%S).txt"
echo "Output file: $output_file"

# Run the scripts
python3 -m onboardUser.scripts.python.gen_account $RPC_NODE_URL
source .env
python3 -m onboardUser.scripts.python.transfer_native_coins $MASTER_KEY $RPC_NODE_URL --amount_to_transfer 3000000
python3 -m onboardUser.scripts.python.onboard_user $RPC_NODE_URL
source .env

success_counter=0
failure_counter=0
# Run the tests in a loop
while true; do
  python3 -m tests.scripts.python.run_precompile_tests_contract $RPC_NODE_URL --output_file $output_file
  if [ $? -eq 0 ]; then
    success_counter=$((success_counter+1))
    echo "Success: $success_counter"
  else
      failure_counter=$((failure_counter+1))
      echo "Failure: $failure_counter"
  fi

  # Get the current time
  current_time=$(date +%s)
  # Check if an hour (3600 seconds) has passed since the last notification
  if (( current_time - last_notification_time >= 3600 )); then
    send_slack_notification "MPC tests are still running: Success tests: $success_counter, Failure tests: $failure_counter"
    last_notification_time=$current_time  # Update the last notification time
  fi

done
