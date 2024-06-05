import os
import sys
sys.path.append('soda-sdk')
from python.crypto import prepare_delete_key_signature
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter
from eth_account import Account
import logging

FILE_NAME = 'GetUserKeyContract.sol'
FILE_PATH = 'onboardUser/contracts/'

def remove_user_key_from_file(filename):
    # Read the content of the file
    with open(filename, 'r') as file:
        all_lines = file.readlines()

    # Filter out the lines containing "USER_KEY"
    temp_lines = list(filter(lambda line: "USER_KEY" not in line, all_lines))

    # Now temp_lines contains only the lines without "USER_KEY"
    # Write the modified content back to the same file
    with open(filename, 'w') as file:
        for line in temp_lines:
            file.write(line)

def get_function_signature(function_abi):
    # Extract the input types from the ABI
    input_types = ','.join([param['type'] for param in function_abi.get('inputs', [])])

    # Generate the function signature
    return f"{function_abi['name']}({input_types})"

def main(provider_url: str):

    signing_key = os.environ.get('SIGNING_KEY')
    account = Account.from_key(signing_key)
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

    # There could be a situation where a request to delete a user's key is hidden within a malicious function. 
    # Unknowingly, the user might activate it, inadvertently causing their key to be deleted. 
    # To prevent such an occurrence, it's essential to confirm that the individual requesting the key deletion is indeed the 
    # key's owner and is fully conscious of the deletion process. 
    # This is achieved by requiring the user's signature on both the user's address and the contract's address, as well as 
    # on the function signature. By mandating the user's signature on the contract and function that entails a key deletion call, 
    # it ensures that the user is informed that their key will be deleted, thereby preventing accidental or malicious deletions.
    
    # To simplify the process of obtaining the function signature, we use a dummy function with placeholder inputs.
    # After the signature is generated, we call prepare input text function and get the input text to use in the real function.
    dummySignature = bytes(65)
    function = contract.functions.deleteUserKey(dummySignature)
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Sign the message
    signature = prepare_delete_key_signature(account, contract, func_sig, bytes.fromhex(signing_key[2:]))

    # Call the deleteUserKey function to delete the encrypted AES shares
    receipt = soda_helper.call_contract_transaction("onboard_user", "deleteUserKey", func_args=[signature])
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    remove_user_key_from_file('.env')

if __name__ == "__main__":
    url = parse_url_parameter()
    if (url is not None):
        try:
            main(url)
        except Exception as e:
            logging.error("An error occurred: %s", e)
    
