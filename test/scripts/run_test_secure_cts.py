import json
import os
from eth_account import Account
from solcx import compile_standard, install_solc, get_installed_solc_versions
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

SOLC_VERSION = '0.8.19'
FILE_PATH = 'TestSecureCts.sol'
PROVIDER_URL = 'http://localhost:7000'
PRIVATE_KEY = "0x2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"

def check_and_install_solc_version(solc_version):
    if solc_version not in get_installed_solc_versions():
        install_solc(solc_version)

def read_solidity_code(file_path):
    if not os.path.exists(file_path):
        raise Exception(f"The file {file_path} does not exist")
    with open(file_path, 'r') as file:
        return file.read()

def compile_solidity(solc_version, file_path, solidity_code, mpc_inst_path, mpc_core_path):
    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": {
            "MPCInst.sol": {"urls": [mpc_inst_path]},
            "MpcCore.sol": {"urls": [mpc_core_path]},
            file_path: {"content": solidity_code},
        },
        "settings": {
            "outputSelection": {
                "*": {"*": ["metadata", "evm.bytecode", "evm.bytecode.sourceMap"]}
            }
        },
    },
    solc_version=solc_version,
    allow_paths=[".", "../solidity_lib"]
    )
    return compiled_sol

def deploy_contract(w3, account, contract_abi, contract_bytecode, gas_limit=1500000, gas_price='30'):
    contract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
    construct_txn = contract.constructor().build_transaction({
        'from': account.address,
        'chainId': 50505050,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': gas_limit,
        'gasPrice': w3.to_wei(gas_price, 'gwei')
    })
    signed_txn = w3.eth.account.sign_transaction(construct_txn, account._private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f'Contract Deployed At Address: {tx_receipt.contractAddress}')
    return w3.eth.contract(address=tx_receipt.contractAddress, abi=contract_abi)


def execute_transaction(w3, account, contract, function, gas_limit=2000000, gas_price='50'):
    transaction = function.build_transaction({
        'from': account.address,
        'chainId': 50505050,
        'gas': gas_limit,
        'gasPrice': w3.to_wei(gas_price, 'gwei'),
        'nonce': w3.eth.get_transaction_count(account.address),
    })
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=account._private_key)
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    txn_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)
    print(f'Transaction successful with hash: {txn_hash.hex()}')
    return txn_receipt

def call_view_functions(account, contract):
    x = contract.functions.GetX().call({'from': account.address})
    print("Function call result x:", x)
    function_call_result = contract.functions.GetCt().call({'from': account.address})
    print("Function call result Ct:", function_call_result)
    function_call_result = contract.functions.GetSecretX().call({'from': account.address})
    print("Function call result secret:", function_call_result)
    function_call_result = contract.functions.GetX().call({'from': account.address})
    print("Function call result:", function_call_result)

    return x

def check_expected_result(name, expected_result, result):
    if result == expected_result:
        print(f'Test {name} succeeded: {result}')
    else:
        raise ValueError(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')


def main():
    check_and_install_solc_version(SOLC_VERSION)
    solidity_code = read_solidity_code(FILE_PATH)

    mpc_inst_path = "../solidity_lib/MPCInst.sol"
    mpc_core_path = "../solidity_lib/MpcCore.sol"
    compiled_sol = compile_solidity(SOLC_VERSION, FILE_PATH, solidity_code, mpc_inst_path, mpc_core_path)

    contract_name = FILE_PATH.split('.')[0]
    bytecode = compiled_sol['contracts'][FILE_PATH][contract_name]['evm']['bytecode']['object']
    contract_abi = json.loads(compiled_sol['contracts'][FILE_PATH][contract_name]['metadata'])['output']['abi']
    contract_bytecode = f'0x{bytecode}'

    w3 = Web3(HTTPProvider(PROVIDER_URL))
    if not w3.is_connected():
        print("Failed to connect to the Ethereum node.")
        exit()

    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    account = Account.from_key(PRIVATE_KEY)
    w3.eth.default_account = account.address

    contract = deploy_contract(w3, account, contract_abi, contract_bytecode)


    #  This functions should return val*2
    val = 5
    function = contract.functions.setGeneratedCtToSecureStorage(val)
    execute_transaction(w3, account, contract, function)

    res = call_view_functions(account, contract)
    check_expected_result("setGeneratedCtToSecureStorage", val*2, res)
   

    #  This functions should return val*2*4
    function = contract.functions.onBoradFromSecureStorage()
    execute_transaction(w3, account, contract, function)

    res = call_view_functions(account, contract)
    check_expected_result("onBoradFromSecureStorage", val*2*4, res)
    
    #  This functions should return val*2*4 as the operation is reverted and the value remains the same
    function = contract.functions.tryOnBoradStolenMemory()
    execute_transaction(w3, account, contract, function)

    res = call_view_functions(account, contract)
    check_expected_result("tryOnBoradStolenMemory", val*2*4, res)

    #  This functions should return val*2*4 as the operation is reverted and the value remains the same
    function = contract.functions.tryOnBoradStolenStorage()
    execute_transaction(w3, account, contract, function)

    res = call_view_functions(account, contract)
    check_expected_result("tryOnBoradStolenStorage", val*2*4, res)
    
    val = 3
    function = contract.functions.setGeneratedCtToSecureStorage(val)
    execute_transaction(w3, account, contract, function)

    res = call_view_functions(account, contract)
    check_expected_result("setGeneratedCtToSecureStorage", val*2, res)

    function = contract.functions.createContractDeepContract()
    execute_transaction(w3, account, contract, function)

    val = 4
    function = contract.functions.testDeep(val)
    execute_transaction(w3, account, contract, function)

    res = call_view_functions(account, contract)
    check_expected_result("testDeep", val*2, res)

    function = contract.functions.testDeepStoredData(val)
    execute_transaction(w3, account, contract, function)
 
    res = call_view_functions(account, contract)
    check_expected_result("testDeepStoredData", val*4, res)
    
    gas_estimate = function.estimate_gas({
        'from': account.address,
    })
    print('Estimated Gas:', gas_estimate)


if __name__ == "__main__":
    main()
