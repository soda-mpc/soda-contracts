import json
import os
from eth_account import Account
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter
import sys
sys.path.append('soda-sdk')
from python.crypto import generate_rsa_keypair, sign, recover_user_key, prepare_delete_key_signature

FILE_NAME = 'GetUserKeyContract.sol'
FILE_PATH = 'onboardUser/contracts/'
SIGNATURE_SIZE = 65

def getUserKeyShares(account, contract, receipt):
    """
    This function retrieves the key shares of a user from a transaction receipt. It processes the receipt 
    to get the UserKey events, then iterates through these events to find the ones that match the provided 
    account address. If it finds matching events, it extracts the key shares from these events. If it doesn't 
    find any matching events, it prints an error message.

    @param {object} account - The account object, which includes the user's address.
    @param {object} contract - The contract object, which includes the contract's events.
    @param {object} receipt - The transaction receipt to process.

    @return {tuple} A tuple containing the two key shares, or (None, None) if no matching events were found.
    """
    user_key_events = contract.events.UserKey().process_receipt(receipt)

    key_0_share = None
    key_1_share = None
    # Filter events for the specific address
    for event in user_key_events:
        if event['args']['_owner'].lower() == account.address.lower():
            key_0_share = event['args']['_keyShare0']
            key_1_share = event['args']['_keyShare1']
    
    if key_0_share is None or key_1_share is None:
        print("Failed to find the key shares of the account address in the transaction receipt.")

    return key_0_share, key_1_share

def getUserKey(signing_key, soda_helper, contract):
    # Generate new RSA key pair
    private_key, public_key = generate_rsa_keypair()
    # Sign the public key
    signature = sign(public_key, bytes.fromhex(signing_key[2:]))

    # Call the getUserKey function to get the encrypted AES shares
    receipt = soda_helper.call_contract_transaction("onboard_user", "getUserKey", func_args=[public_key, signature])
    if receipt is None:
        print("Failed to call the transaction function")
        return

    encryptedKey0, encryptedKey1 = getUserKeyShares(soda_helper.get_account(), contract, receipt)

    # Recover the aes key using the RSA private key and the given shares
    return recover_user_key(private_key, encryptedKey0, encryptedKey1)
    
def get_function_signature(function_abi):
    # Extract the input types from the ABI
    input_types = ','.join([param['type'] for param in function_abi.get('inputs', [])])

    # Generate the function signature
    return f"{function_abi['name']}({input_types})"

def deleteKey(signing_key, soda_helper, contract, account):
    dummySignature = bytes(SIGNATURE_SIZE)
    function = contract.functions.deleteUserKey(dummySignature)
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Sign the message
    signature = prepare_delete_key_signature(account, contract, func_sig, bytes.fromhex(signing_key[2:]))

    # Call the deleteUserKey function to delete the encrypted AES shares
    receipt = soda_helper.call_contract_transaction("onboard_user", "deleteUserKey", func_args=[signature])
    if receipt is None:
        print("Failed to call the transaction function")
        return

def main(provider_url: str):

    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)
    account = soda_helper.get_account()

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, "onboard_user")
    if not success:
        print("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("onboard_user", constructor_args=[])
    if receipt is None:
        print("Failed to deploy the contract")

    contract = soda_helper.get_contract("onboard_user")
    

    # Get user key
    user_key1 = getUserKey(signing_key, soda_helper, contract)
    print(f'User key: {user_key1.hex()}')
    # Get user key again. Should be equal
    user_key2 = getUserKey(signing_key, soda_helper, contract)
    if user_key1 == user_key2:
        print(f'Test user key succeeded: Got 2 equal keys')
    else:
        raise ValueError(f'Test user key failed. Got different values: {user_key1} and {user_key2}')

    # Delete user key
    deleteKey(signing_key, soda_helper, contract, account)
    print('User key deleted')
    # Get user key again. Should be different
    user_key2 = getUserKey(signing_key, soda_helper, contract)
    print(f'User key: {user_key2.hex()}')

    if user_key1 != user_key2:
        print(f'Test user key succeeded: Got 2 different keys')
    else:
        raise ValueError(f'Test user key failed. Got the same value: {user_key1}')

    


if __name__ == "__main__":
    url = parse_url_parameter()
    if (url is not None):
        main(url)

