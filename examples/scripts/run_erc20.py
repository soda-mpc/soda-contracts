import json
import os
import sys
from eth_account import Account
from solcx import compile_standard, install_solc, get_installed_solc_versions
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), '../../tools/python')))
from crypto import decrypt, prepare_IT
import subprocess

SOLC_VERSION = '0.8.19'
FILE_PATH = 'ERC20TokenStandardContract.sol'
PROVIDER_URL = 'http://localhost:7000'
INITIAL_BALANCE = 500000000

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
    allow_paths=[".", "../../lib/solidity"]
    )
    return compiled_sol

def deploy_contract(w3, account, contract_abi, contract_bytecode, gas_limit=10000000, gas_price='30'):
    contract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
    construct_txn = contract.constructor("Soda", "SOD", INITIAL_BALANCE).build_transaction({
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


def execute_transaction(w3, account, function, gas_limit=2000000, gas_price='50'):
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


def check_expected_result(name, expected_result, result):
    if result == expected_result:
        print(f'Test {name} succeeded: {result}')
    else:
        raise ValueError(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')


def decrypt_value(my_CTBalance, user_key):
    
    # Convert ct to bytes (big-endian)
    byte_array = my_CTBalance.to_bytes(32, byteorder='big')

    # Split ct into two 128-bit arrays r and cipher
    cipher = byte_array[:16]
    r = byte_array[16:]

    # Decrypt the cipher
    decrypted_message = decrypt(user_key, r, cipher)

    # Print the decrypted cipher
    decrypted_balance = int.from_bytes(decrypted_message, 'big')

    return decrypted_balance
    

def get_function_signature(function_abi):
    # Extract the input types from the ABI
    input_types = ','.join([param['type'] for param in function_abi.get('inputs', [])])

    # Generate the function signature
    return f"{function_abi['name']}({input_types})"

def execute_and_check_balance(w3, account, contract, function, user_key, name, expected_balance):
    execute_transaction(w3, account, function)
    # Get my encrypted balance, decrypt it and check if it matches the expected value
    my_CTBalance = contract.functions.balanceOf().call({'from': account.address})
    my_balance = decrypt_value(my_CTBalance, user_key)
    check_expected_result(name, expected_balance, my_balance)

def check_allowance(account, contract, user_key, expected_allowance):
    # Get my encrypted allowance, decrypt it and check if it matches the expected value
    allowanceCT = contract.functions.allowance(account.address, account.address).call({'from': account.address})
    allowance = decrypt_value(allowanceCT, user_key)
    check_expected_result('allowance', expected_allowance, allowance)

def check_expected_result(name, expected_result, result):
    if result == expected_result:
        print(f'Test {name} succeeded: {result}')
    else:
        raise ValueError(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')

def main():
    check_and_install_solc_version(SOLC_VERSION)
    solidity_code = read_solidity_code("../contracts/" + FILE_PATH)

    mpc_inst_path = "../../lib/solidity/MPCInst.sol"
    mpc_core_path = "../../lib/solidity/MpcCore.sol"
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

    private_key = os.environ.get('SIGNING_KEY')
    account = Account.from_key(private_key)
    w3.eth.default_account = account.address

    contract = deploy_contract(w3, account, contract_abi, contract_bytecode)

    print("************* View functions *************")
    name = contract.functions.name().call({'from': account.address})
    print("Function call result name:", name)

    symbol = contract.functions.symbol().call({'from': account.address})
    print("Function call result symbol:", symbol)

    decimals = contract.functions.decimals().call({'from': account.address})
    print("Function call result decimals:", decimals)

    totalSupply = contract.functions.totalSupply().call({'from': account.address})
    print("Function call result totalSupply:", totalSupply)

    user_key_hex = os.environ.get('USER_KEY')
    user_key = bytes.fromhex(user_key_hex)  


    print("************* Initial balance = ", INITIAL_BALANCE, " *************")
    my_CTBalance = contract.functions.balanceOf().call({'from': account.address})
    my_balance = decrypt_value(my_CTBalance, user_key)
    check_expected_result('balanceOf', INITIAL_BALANCE, my_balance)

    # Generate a new Ethereum account for Alice
    alice_address = Account.create()

    plaintext_integer = 5

    print("************* Transfer clear ", plaintext_integer, " to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.transfer(alice_address.address, plaintext_integer, True)
    execute_and_check_balance(w3, account, contract, function, user_key, 'transfer', INITIAL_BALANCE - plaintext_integer)

    print("************* Transfer clear ", plaintext_integer, " to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.contractTransferClear(alice_address.address, plaintext_integer)
    execute_and_check_balance(w3, account, contract, function, user_key, 'contract transfer clear', INITIAL_BALANCE - 2*plaintext_integer)

    print("************* Transfer IT ", plaintext_integer, " to Alice *************")
    # In order to generate the input text, we need to use some data of the function. 
    # For example, the address of the user, the address of the contract and also the function signature.
    # In order to get the function signature as simple as possible, we decided to use a dummy function with dummy inputs and use it to generate the signature.
    # After the signature is generated, we call prepare input text function and get the input text to use in the real function.
    dummyCT = 0
    dummySignature = bytes(65)
    function = contract.functions.transfer(alice_address.address, dummyCT, dummySignature, False)
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(plaintext_integer, user_key, account, contract, func_sig, bytes.fromhex(private_key[2:]))
    # Create the real function using the prepared IT
    function = contract.functions.transfer(alice_address.address, ct, signature, False)
    # Transfer 5 SOD to Alice
    execute_and_check_balance(w3, account, contract, function, user_key, 'transfer IT', INITIAL_BALANCE - 3*plaintext_integer)

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice without allowance *************")
    # Trying to transfer 5 SOD to Alice. There is no allowance, transfer should fail
    function = contract.functions.transferFrom(account.address, alice_address.address, plaintext_integer, True)
    execute_and_check_balance(w3, account, contract, function, user_key, 'transfer from', INITIAL_BALANCE - 3*plaintext_integer)

    print("************* Approve ", plaintext_integer*10, " to my address *************")
    # Set allowance for this account
    function = contract.functions.approveClear(account.address, plaintext_integer*10)
    execute_transaction(w3, account, function)
    # Get my allowance to check that the allowance is correct
    check_allowance(account, contract, user_key, plaintext_integer*10)

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.transferFrom(account.address, alice_address.address, plaintext_integer, True)
    execute_and_check_balance(w3, account, contract, function, user_key, 'transfer from', INITIAL_BALANCE - 4*plaintext_integer)

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.contractTransferFromClear(account.address, alice_address.address, plaintext_integer)
    execute_and_check_balance(w3, account, contract, function, user_key, 'contract transfer from clear ', INITIAL_BALANCE - 5*plaintext_integer)

    print("************* Transfer IT ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.transferFrom(account.address, alice_address.address, dummyCT, dummySignature, False) # Dummy function
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(plaintext_integer, user_key, account, contract, func_sig, bytes.fromhex(private_key[2:]))
    # Create the real function using the prepared IT
    function = contract.functions.transferFrom(account.address, alice_address.address, ct, signature, False)
    execute_and_check_balance(w3, account, contract, function, user_key, 'transfer from IT', INITIAL_BALANCE - 6*plaintext_integer)
    
    print("************* Check my allowance *************")
    # Check the remainning allowance
    check_allowance(account, contract, user_key, plaintext_integer*7)

    print("************* Approve IT 50 to my address *************")
    # Approve 50 SOD to this account
    function = contract.functions.approve(account.address, dummyCT, dummySignature) # Dummy function
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(50, user_key, account, contract, func_sig, bytes.fromhex(private_key[2:]))
    function = contract.functions.approve(account.address, ct, signature)
    execute_transaction(w3, account, function)

    print("************* Check my allowance *************")
    # Check that the allowance has changed to 50 SOD
    check_allowance(account, contract, user_key, 50)




if __name__ == "__main__":
    main()
