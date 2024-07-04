import logging
import os
from eth_account import Account
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter

FILE_NAME = 'TestSecureCts.sol'
FILE_PATH = 'tests/contracts/'

def execute_transaction(soda_helper, function):  
    receipt = soda_helper.call_contract_function_transaction("secure_cts", function)
    if receipt is None:
        raise Exception("Failed to call the transaction function")

def call_view_functions(account, contract):
    x = contract.functions.GetX().call({'from': account.address})
    print("Function call result x:", x)
    function_call_result = contract.functions.GetCt().call({'from': account.address})
    print("Function call result Ct:", function_call_result)
    function_call_result = contract.functions.GetX().call({'from': account.address})
    print("Function call result:", function_call_result)

    return x

def check_expected_result(name, expected_result, result):
    if result == expected_result:
        print(f'Test {name} succeeded: {result}')
    else:
        raise ValueError(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')


def main(provider_url: str):

    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)
    account = soda_helper.get_account()

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, "secure_cts")
    if not success:
        raise Exception("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("secure_cts", constructor_args=[])
    if receipt is None:
        raise Exception("Failed to deploy the contract")

    contract = soda_helper.get_contract("secure_cts")
    

    #  This functions should return val*2
    val = 5
    function = contract.functions.setGeneratedCtToSecureStorage(val)
    execute_transaction(soda_helper, function)

    res = call_view_functions(account, contract)
    check_expected_result("setGeneratedCtToSecureStorage", val*2, res)
   

    #  This functions should return val*2*4
    function = contract.functions.onBoradFromSecureStorage()
    execute_transaction(soda_helper, function)

    res = call_view_functions(account, contract)
    check_expected_result("onBoradFromSecureStorage", val*2*4, res)
    
    #  This functions should return val*2*4 as the operation is reverted and the value remains the same
    function = contract.functions.tryOnBoradStolenMemory()
    execute_transaction(soda_helper, function)

    res = call_view_functions(account, contract)
    check_expected_result("tryOnBoradStolenMemory", val*2*4, res)

    #  This functions should return val*2*4 as the operation is reverted and the value remains the same
    function = contract.functions.tryOnBoradStolenStorage()
    execute_transaction(soda_helper, function)

    res = call_view_functions(account, contract)
    check_expected_result("tryOnBoradStolenStorage", val*2*4, res)
    
    val = 3
    function = contract.functions.setGeneratedCtToSecureStorage(val)
    execute_transaction(soda_helper, function)

    res = call_view_functions(account, contract)
    check_expected_result("setGeneratedCtToSecureStorage", val*2, res)

    function = contract.functions.createContractDeepContract()
    execute_transaction(soda_helper, function)
    
    val = 4
    function = contract.functions.testDeep(val)
    execute_transaction(soda_helper, function)
    
    res = call_view_functions(account, contract)
    check_expected_result("testDeep", val*2, res)

    function = contract.functions.testDeepStoredData(val)
    execute_transaction(soda_helper, function)

    res = call_view_functions(account, contract)
    check_expected_result("testDeepStoredData", val*4, res)
    
    gas_estimate = function.estimate_gas({
        'from': account.address,
    })
    print('Estimated Gas:', gas_estimate)


if __name__ == "__main__":
    url = parse_url_parameter()
    if (url is not None):
        try:
            main(url)
        except Exception as e:
            logging.error("An error occurred: %s", e)
            raise e

