import os
from soda_python_sdk import generate_rsa_keypair, sign, recover_user_key
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter
import logging

FILE_NAME = 'GetUserKeyContract.sol'
FILE_PATH = 'onboardUser/contracts/'

def remove_user_key_from_file(filename):
    # Read the content of the file
    with open(filename, 'r') as file:
        all_lines = file.readlines()

    # Filter out the lines containing "USER_KEY"
    temp_lines = list(filter(lambda line: "USER_KEY" not in line, all_lines))

    # Write the modified content back to the same file
    with open(filename, 'w') as file:
        for line in temp_lines:
            file.write(line)

def getUserKeyShares(account, contract, receipt):
    user_key_events = contract.events.UserKey().process_receipt(receipt)

    key_0_share = None
    key_1_share = None
    # Filter events for the specific address
    for event in user_key_events:
        if event['args']['_owner'].lower() == account.address.lower():
            key_0_share = event['args']['_keyShare0']
            key_1_share = event['args']['_keyShare1']
    
    if key_0_share is None or key_1_share is None:
        raise Exception("Failed to find the key shares of the account address in the transaction receipt.")

    return key_0_share, key_1_share

def main(provider_url: str):

    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, "onboard_user")
    if not success:
        raise Exception("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("onboard_user", constructor_args=[])
    if receipt is None:
        raise Exception("Failed to deploy the contract")

    contract = soda_helper.get_contract("onboard_user")
    
    # Generate new RSA key pair
    private_key, public_key = generate_rsa_keypair()
    # Sign the public key
    signature = sign(public_key, bytes.fromhex(signing_key[2:]))

    # Call the getUserKey function to get the encrypted AES shares
    receipt = soda_helper.call_contract_transaction("onboard_user", "getUserKey", func_args=[public_key, signature])
    if receipt is None:
        raise Exception("Failed to call the transaction function")

    encryptedKey0, encryptedKey1 = getUserKeyShares(soda_helper.get_account(), contract, receipt)

    # Recover the aes key using the RSA private key and the given shares
    decrypted_aes_key = recover_user_key(private_key, encryptedKey0, encryptedKey1)
    
    # Remove the old USER_KEY from the .env file
    remove_user_key_from_file('.env')

    # Write the data to a .env file
    with open('.env', 'a') as f:
        f.write(f"export USER_KEY='{decrypted_aes_key.hex()}'\n")


if __name__ == "__main__":
    url = parse_url_parameter()
    if (url is not None):
        try:
            main(url)
        except Exception as e:
            logging.error("An error occurred: %s", e)
            raise e
    
