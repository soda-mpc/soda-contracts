import os
import sys
sys.path.append('soda-sdk')
from python.crypto import sign
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter
from time import sleep

FILE_NAME = 'GetUserKeyContract.sol'
FILE_PATH = 'onboardUser/contracts/'

def remove_user_key_from_file(filename):
    # Temporary list to hold lines that do not contain "USER_KEY"
    temp_lines = []

    # Read the original file and filter out the line containing "USER_KEY"
    with open(filename, 'r') as file:
        for line in file:
            if "USER_KEY" not in line:
                temp_lines.append(line)

    # Write the modified content back to the same file
    with open(filename, 'w') as file:
        for line in temp_lines:
            file.write(line)

def main(provider_url: str):

    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, "onboard_user")
    if not success:
        print("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("onboard_user", constructor_args=[])
    if receipt is None:
        print("Failed to deploy the contract")

    contract = soda_helper.get_contract("onboard_user")

    # Sign the address
    signature = sign(bytes.fromhex(soda_helper.account.address[2:]), bytes.fromhex(signing_key[2:]))

    # Call the deleteUserKey function to delete the encrypted AES shares
    receipt = soda_helper.call_contract_transaction("onboard_user", "deleteUserKey", func_args=[signature])
    if receipt is None:
        print("Failed to call the transaction function")
        return
    
    remove_user_key_from_file('.env')

if __name__ == "__main__":
    url = parse_url_parameter()
    if (url is not None):
        main(url)
    
