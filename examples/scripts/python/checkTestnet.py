import os
from eth_account import Account
import sys
from time import sleep
sys.path.append('soda-sdk')
from python.crypto import decrypt, prepare_IT, block_size
from lib.python.soda_web3_helper import SodaWeb3Helper, LOCAL_PROVIDER_URL

FILE_NAME = 'CheckTestnet.sol'
FILE_PATH = 'examples/contracts/'

def main():
    # Get the account private key from the environment variable
    private_key = os.environ.get('SIGNING_KEY')
    account = Account.from_key(private_key)

    soda_helper = SodaWeb3Helper(private_key, LOCAL_PROVIDER_URL)

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, "check_testnet")
    if not success:
        print("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("check_testnet")
    if receipt is None:
        print("Failed to deploy the contract")

    print("block number:", receipt.blockNumber)

    contract = soda_helper.get_contract("check_testnet")

    print("contract:", contract)
    
    
    function = contract.functions.test()
    receipt = soda_helper.call_contract_function_transaction("check_testnet", function)

    print("block number:", receipt.blockNumber)


    print(soda_helper.web3.eth.get_block(receipt.blockNumber).transactions)
    print(soda_helper.web3.eth.get_block(receipt.blockNumber).difficulty)


    if receipt is None:
        print("Failed to call the transaction function")

    # Get the output
    output = contract.functions.getOutput().call({'from': account.address})
    print("Function call result:", output)

    sleep(30)

    # Get the output
    output = contract.functions.getOutput().call({'from': account.address})
    print("Function call result:", output)

    output = contract.functions.getBoolOutput().call({'from': account.address})
    print("Function call bool result:", output)


if __name__ == "__main__":
    main()
