import os
import sys
from eth_account import Account
from lib.python.soda_web3_helper import SodaWeb3Helper, DEFAULT_GAS_PRICE, REMOTE_HTTP_PROVIDER_URL
import argparse

def transfer_to_account(sender_account_key, receiver_account):
    soda_helper = SodaWeb3Helper(sender_account_key, REMOTE_HTTP_PROVIDER_URL)
    sender_balance = soda_helper.get_native_currency_balance(soda_helper.account.address)
    original_receiver_balance = soda_helper.get_native_currency_balance(receiver_account.address)
    if sender_balance is None:
        print("Failed to get the balance of the account")
    amount_to_transfer = 3000  # in SOD, an ether-like unit
    receipt = soda_helper.transfer_native_currency(receiver_account.address, amount_to_transfer)
    # We check the balance of the accounts after the transfer is complete
    receiver_balance = soda_helper.get_native_currency_balance(receiver_account.address)
    assert receiver_balance == original_receiver_balance + soda_helper.convert_sod_to_wei(amount_to_transfer)
    print(f"Balance of the receiver account: {receiver_balance}")
    

def main(sender_account_key):
    signing_key = os.environ.get('SIGNING_KEY')
    receiver_account = Account.from_key(signing_key)
    print(f"Receiver account address: {receiver_account.address}")
    transfer_to_account(sender_account_key, receiver_account)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('sender_account_key', type=str, help='The private key of the sender account')
    args = parser.parse_args()
    main(args.sender_account_key)

