import logging
import os
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter
import hashlib

FILE_NAME = 'PrecompilesSHATestsContract.sol'
FILE_PATH = 'tests/contracts/'


def getSHAOutput(account, contract, receipt):
    sha_events = contract.events.SHAOutput().process_receipt(receipt)
    if len(sha_events) == 0:
        raise Exception("Failed to find the sha output event in the transaction receipt.")

    result = None
    # Filter events for the specific address
    for event in sha_events:
        if event['args']['_owner'].lower() == account.address.lower():
            result = event['args']['_shaOutput']
    
    if result is None :
        raise Exception("Failed to find the sha output of the account address in the transaction receipt.")

    return result

def main(provider_url: str):

    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)
    account = soda_helper.get_account()

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, "sha_test")
    if not success:
        raise Exception("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("sha_test", constructor_args=[])
    if receipt is None:
        raise Exception("Failed to deploy the contract")

    receipt = soda_helper.call_contract_transaction("sha_test", "sha256Fixed432BitInputTest", func_args=[0, 0, 0, account.address, 0, 0])
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    result = getSHAOutput(account, soda_helper.get_contract("sha_test"), receipt)
    if result is None:
        raise Exception("Failed to call the view function")
    
    result = result.hex()
    
    zero64 = bytes(8) # Represents 64 bits of zeros
    zero16 = bytes(2) # Represents 16 bits of zeros
    address_bytes = bytes.fromhex(account.address[2:])
    data = zero64 + zero64 + zero64 + address_bytes + zero64 + zero16
    hash_object = hashlib.sha256(data)
    expected_result = hash_object.digest().hex()

    if result == expected_result:
        print(f'Test sha256Fixed432BitInput succeeded: {result}')
    else:
        raise ValueError(f'Test sha256Fixed432BitInput failed. Expected: {expected_result}, Actual: {result}')

if __name__ == "__main__":
    url = parse_url_parameter()
    if (url is not None):
        try:
            main(url)
        except Exception as e:
            logging.error("An error occurred: %s", e)
            raise e
            
