import os
import sys
from eth_account import Account
from lib.python.soda_web3_helper import SodaWeb3Helper, DEFAULT_GAS_PRICE, LOCAL_PROVIDER_URL, REMOTE_HTTP_PROVIDER_URL
import argparse

def transfer_to_account(sender_account_key, receiver_account, provider_url, amount_to_transfer=3000):
    print(f"Sender account key: {sender_account_key}")
    soda_helper = SodaWeb3Helper(sender_account_key, provider_url)
    sender_balance = soda_helper.get_native_currency_balance(soda_helper.account.address)
    original_receiver_balance = soda_helper.get_native_currency_balance(receiver_account.address)
    print(f"Balance of the sender account: {sender_balance}")
    if sender_balance is None:
        print("Failed to get the balance of the account")
    receipt = soda_helper.transfer_native_currency(receiver_account.address, amount_to_transfer)
    # We check the balance of the accounts after the transfer is complete
    receiver_balance = soda_helper.get_native_currency_balance(receiver_account.address)
    assert receiver_balance == original_receiver_balance + soda_helper.convert_sod_to_wei(amount_to_transfer)
    print(f"Balance of the receiver account: {receiver_balance}")
    

def main(sender_account_key, provider_url, amount_to_transfer=3000):
    signing_key = os.environ.get('SIGNING_KEY')
    receiver_account = Account.from_key(signing_key)
    print(f"Receiver account address: {receiver_account.address}")
    transfer_to_account(sender_account_key, receiver_account, provider_url, amount_to_transfer)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('sender_account_key', type=str, help='The private key of the sender account')
    parser.add_argument('provider_url', type=str, help='The node url')
    parser.add_argument('--amount_to_transfer', type=int, default=3000, help='The amount to transfer')
    args = parser.parse_args()
    print(f'Provider URL: {args.provider_url}')
    if not args.provider_url:
        raise ValueError("Please provide the provider url")
    if args.provider_url == "Local":
        main(args.sender_account_key, LOCAL_PROVIDER_URL)
    elif args.provider_url == "Remote":
        main(args.sender_account_key, REMOTE_HTTP_PROVIDER_URL)
    else:
        main(args.sender_account_key, args.provider_url, args.amount_to_transfer)
