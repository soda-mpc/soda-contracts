import json
import os
import sys

from eth_account import Account
from solcx import compile_standard, install_solc, get_installed_solc_versions
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), '../../tools/python')))
from crypto import generate_aes_key, write_aes_key, generate_rsa_keypair, decrypt_rsa, encrypt_rsa, sign, decrypt

# Specify the Solidity version
SOLC_VERSION = '0.8.19'
# Path to the Solidity files
SOLIDITY_FILES = ['PrecompilesArythmeticTestsContract.sol', 
                  'PrecompilesBitwiseTestsContract.sol', 
                  'PrecompilesComparison2TestsContract.sol', 
                  'PrecompilesMiscellaneousTestsContract.sol',
                  'PrecompilesMiscellaneous1TestsContract.sol',
                  'PrecompilesTransferTestsContract.sol', 
                  'PrecompilesTransferScalarTestsContract.sol', 
                  'PrecompilesMinMaxTestsContract.sol', 
                  'PrecompilesShiftTestsContract.sol', 
                  'PrecompilesComparison1TestsContract.sol',
                  'PrecompilesOffboardToUserKeyTestContract.sol']
# The exposed port for the local node 
PROVIDER_URL = 'http://localhost:7000'
# The ley corresponding to the deployer account
PRIVATE_KEY = "0x2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"

def check_and_install_solc_version(solc_version):
    if solc_version not in get_installed_solc_versions():
        install_solc(solc_version)

def read_solidity_code():
    # Ensure the file paths are valid
    for file_path in SOLIDITY_FILES:
        if not os.path.exists("../contracts/" + file_path):
            raise Exception(f"The file {file_path} does not exist")

    # Read the Solidity source code from the files
    solidity_sources = {}
    for file_path in SOLIDITY_FILES:
        file_path = "../contracts/" + file_path
        with open(file_path, 'r') as file:
            solidity_sources[file_path] = file.read()
    
    return solidity_sources

def compile_solidity(solidity_sources, mpc_inst_path, mpc_core_path):
    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": {
            "MPCInst.sol": {"urls": [mpc_inst_path]},
            "MpcCore.sol": {"urls": [mpc_core_path]},
            SOLIDITY_FILES[0]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[0]]}, 
            SOLIDITY_FILES[1]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[1]]}, 
            SOLIDITY_FILES[2]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[2]]}, 
            SOLIDITY_FILES[3]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[3]]}, 
            SOLIDITY_FILES[4]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[4]]}, 
            SOLIDITY_FILES[5]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[5]]}, 
            SOLIDITY_FILES[6]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[6]]}, 
            SOLIDITY_FILES[7]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[7]]}, 
            SOLIDITY_FILES[8]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[8]]}, 
            SOLIDITY_FILES[9]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[9]]}, 
            SOLIDITY_FILES[10]: {"content": solidity_sources["../contracts/" + SOLIDITY_FILES[10]]}, 
            # Add other Solidity files as needed
        },
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["metadata", "evm.bytecode", "evm.bytecode.sourceMap"]
                }
            }
            
        },
    },
    solc_version=SOLC_VERSION,
    allow_paths=[".", "../../lib/solidity"]
    )
    return compiled_sol

def deploy_contract(compiled_sol, w3, account, gas_limit=1500000, gas_price='30'):
    # Create a dictionary to store contract instances
    contract_instances = {}

    # Iterate over the compiled contracts
    for file_path in SOLIDITY_FILES:
        # Extract bytecode and ABI
        contract_name = file_path.split('.')[0]
        print(f'Contract Name: {contract_name}')
        bytecode = compiled_sol['contracts'][file_path][contract_name]['evm']['bytecode']['object']
        contract_abi = json.loads(compiled_sol['contracts'][file_path][contract_name]['metadata'])['output']['abi']

        contract_bytecode = f'0x{bytecode}'

        # Contract object
        contract_instance = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)

        # Build transaction
        construct_txn = contract_instance.constructor().build_transaction({
            'from': account.address,
            'chainId': 50505050,
            'nonce': w3.eth.get_transaction_count(account.address),
            'gas': 10000000,  # Adjust the gas limit as needed
            'gasPrice': w3.to_wei('30', 'gwei')  # Set the gas price
        })

        # Sign the transaction
        signed_txn = w3.eth.account.sign_transaction(construct_txn, PRIVATE_KEY)

        # Send the transaction
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)

        # Wait for the transaction to be mined
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        print(f'Contract Deployed At Address for {file_path}: {tx_receipt.contractAddress}')

        # Store the contract instance in the dictionary
        contract_instances[file_path] = w3.eth.contract(address=tx_receipt.contractAddress, abi=contract_abi)

    return contract_instances


def execute_transaction(w3, account, contract, function, gas_limit=4000000, gas_price='50'):
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
    return txn_receipt

def setup():
    # Check if the solc version is already installed, if not, install it
    check_and_install_solc_version(SOLC_VERSION)
    solidity_code = read_solidity_code()

    # Define the file paths for your Solidity files
    mpc_inst_path = "../../lib/solidity/MPCInst.sol"
    mpc_core_path = "../../lib/solidity/MpcCore.sol"

    compiled_sol = compile_solidity(solidity_code, mpc_inst_path, mpc_core_path)

    # Create a Web3 connection to the Ethereum node
    w3 = Web3(HTTPProvider(PROVIDER_URL))

    # Check if connected to the Ethereum node
    if not w3.is_connected():
        print("Failed to connect to the Ethereum node.")
        exit()

    # Inject the poa compatibility middleware to the innermost layer
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Decrypt the keystore
    account = Account.from_key(PRIVATE_KEY)

    # Set default account (you need to have enough ETH to deploy the contract)
    w3.eth.default_account = account.address
    print(f'Account address is {account.address}')

    contract_instances = deploy_contract(compiled_sol, w3, account)

    return contract_instances, account, w3


def execute_and_check_result(name, expected_result, w3, account, contract, function):
    execute_transaction(w3, account, contract, function)
    result = contract.functions.getResult().call()
    check_expected_result(name, expected_result, result)

def check_expected_result(name, expected_result, result):
    if result == expected_result:
        print(f'Test {name} succeeded: {result}')
    else:
        raise ValueError(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')


# Test functions
def test_addition(w3, account, contract, a, b, expected_result):
    function = contract.functions.addTest(a, b)
    execute_and_check_result("addition", expected_result, w3, account, contract, function)

def test_subtraction(w3, account, contract, a, b, expected_result):
    function = contract.functions.subTest(a, b)
    execute_and_check_result("subtraction", expected_result, w3, account, contract, function)

def test_multiplication(w3, account, contract, a, b, expected_result):
    function = contract.functions.mulTest(a, b)
    execute_transaction(w3, account, contract, function)
    result = contract.functions.getResult16().call()
    check_expected_result("multiplication", expected_result, result)

def test_division(w3, account, contract, a, b, expected_result):
    function = contract.functions.divTest(a, b)
    execute_and_check_result("division", expected_result, w3, account, contract, function)

def test_remainder(w3, account, contract, a, b, expected_result):
    function = contract.functions.remTest(a, b)
    execute_and_check_result("reminder", expected_result, w3, account, contract, function)

def test_bitwise_and(w3, account, contract, a, b, expected_result):
    function = contract.functions.andTest(a, b)
    execute_and_check_result("bitwise and", expected_result, w3, account, contract, function)

def test_bitwise_or(w3, account, contract, a, b, expected_result):
    function = contract.functions.orTest(a, b)
    execute_and_check_result("bitwise or", expected_result, w3, account, contract, function)

def test_bitwise_xor(w3, account, contract, a, b, expected_result):
    function = contract.functions.xorTest(a, b)
    execute_and_check_result("bitwise xor", expected_result, w3, account, contract, function)

def test_bitwise_shift_left(w3, account, contract, a, b, expected_result8, expected_result16, expected_result32, expected_result64):
    function = contract.functions.shlTest(a, b)
    execute_transaction(w3, account, contract, function)
    result8, result16, result32, result64 = contract.functions.getAllShiftResults().call()
    check_expected_result("bitwise shift left 8", expected_result8, result8)
    check_expected_result("bitwise shift left 16", expected_result16, result16)
    check_expected_result("bitwise shift left 32", expected_result32, result32)
    check_expected_result("bitwise shift left 64", expected_result64, result64)

def test_bitwise_shift_right(w3, account, contract, a, b, expected_result):
    function = contract.functions.shrTest(a, b)
    execute_and_check_result("bitwise shift right", expected_result, w3, account, contract, function)

def test_min(w3, account, contract, a, b, expected_result):
    function = contract.functions.minTest(a, b)
    execute_and_check_result("min", expected_result, w3, account, contract, function)

def test_max(w3, account, contract, a, b, expected_result):
    function = contract.functions.maxTest(a, b)
    execute_and_check_result("max", expected_result, w3, account, contract, function)

def test_eq(w3, account, contract, a, b, expected_result):
    function = contract.functions.eqTest(a, b)
    execute_and_check_result("equality", expected_result, w3, account, contract, function)

def test_ne(w3, account, contract, a, b, expected_result):
    function = contract.functions.neTest(a, b)
    execute_and_check_result("not equal", expected_result, w3, account, contract, function)

def test_ge(w3, account, contract, a, b, expected_result):
    function = contract.functions.geTest(a, b)
    execute_and_check_result("greater than or equal", expected_result, w3, account, contract, function)

def test_gt(w3, account, contract, a, b, expected_result):
    function = contract.functions.gtTest(a, b)
    execute_and_check_result("greater than", expected_result, w3, account, contract, function)

def test_le(w3, account, contract, a, b, expected_result):
    function = contract.functions.leTest(a, b)
    execute_and_check_result("less than or equal", expected_result, w3, account, contract, function)

def test_lt(w3, account, contract, a, b, expected_result):
    function = contract.functions.ltTest(a, b)
    execute_and_check_result("less than", expected_result, w3, account, contract, function)

def test_mux(w3, account, contract, selectionBit, a, b, expected_result):
    function = contract.functions.muxTest(selectionBit, a, b)
    execute_and_check_result("mux", expected_result, w3, account, contract, function)

def test_transfer(w3, account, contract, a, b, amount, expected_result_a, expected_result_b):
    # new_a, new_b, res = contract.functions.transferTest(a, b, amount).call()
    function = contract.functions.transferTest(a, b, amount)
    execute_transaction(w3, account, contract, function)
    new_a, new_b, res = contract.functions.getResults().call()
    if not res:
        print(f'Test transfer Failed.')
    
    check_expected_result("transfer", expected_result_a, new_a)
    check_expected_result("transfer", expected_result_b, new_b)

def test_offboardOnboard(w3, account, contract, a, expected_result):
    function = contract.functions.offboardOnboardTest(a, a, a, a)
    execute_and_check_result("offboard_Onboard", expected_result, w3, account, contract, function)

def test_not(w3, account, contract, bit, expected_result):
    function = contract.functions.notTest(bit)
    execute_transaction(w3, account, contract, function)
    result = contract.functions.getBoolResult().call()
    check_expected_result("not", expected_result, result)
 
def checkCt(ct, decrypted_aes_key, expected_result):
    # Convert ct to bytes (big-endian)
    byte_array = ct.to_bytes(32, byteorder='big')

    # Split ct into two 128-bit arrays r and cipher
    cipher = byte_array[:16]
    r = byte_array[16:]

    # Decrypt the cipher
    decrypted_message = decrypt(decrypted_aes_key, r, cipher)

    # Print the decrypted cipher
    x = int.from_bytes(decrypted_message, 'big')
    check_expected_result("userKey", expected_result, x)

def test_getUserKey(w3, account, contract, a, expected_result):
    private_key, public_key = generate_rsa_keypair()
    signedEK = sign(public_key, bytes.fromhex("2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"))
    encryptedUserKey = contract.functions.userKeyTest(public_key, signedEK).call()
    decrypted_aes_key = decrypt_rsa(private_key, encryptedUserKey)

    function = contract.functions.offboardToUserTest(a, account.address)
    execute_transaction(w3, account, contract, function)
    ct8, ct16, ct32, ct64 = contract.functions.getCTs().call()
    checkCt(ct8, decrypted_aes_key, expected_result)
    checkCt(ct16, decrypted_aes_key, expected_result)
    checkCt(ct32, decrypted_aes_key, expected_result)
    checkCt(ct64, decrypted_aes_key, expected_result)

last_random_result = 0

def test_random(w3, account, contract):
    global last_random_result  # Use the global keyword to use and modify the global variable
    function = contract.functions.randomTest()
    execute_transaction(w3, account, contract, function)
    result = contract.functions.getRandom().call()
    if result != last_random_result:
        print(f'Test Random succeeded: {result}')
        last_random_result = result
    else:
        raise ValueError(f'Test Random failed.')

def test_randomBoundedBits(w3, account, contract, numBits):
    global last_random_result  # Use the global keyword to use and modify the global variable
    function = contract.functions.randomBoundedTest(numBits)
    execute_transaction(w3, account, contract, function)
    result = contract.functions.getRandom().call()
    if result != last_random_result:
        print(f'Test RandomBoundedBits succeeded: {result}')
        last_random_result = result
    else:
        raise ValueError(f'Test RandomBoundedBits failed.')

# Main test function
def run_tests(contract_instances, account, w3, a, b, shift, bit, numBits):
    # Test Addition
    test_addition(w3, account, contract_instances['PrecompilesArythmeticTestsContract.sol'], a, b, a + b)
    
    # Test Subtraction
    test_subtraction(w3, account, contract_instances['PrecompilesArythmeticTestsContract.sol'], a, b, a - b)

    # Test Multiplication
    test_multiplication(w3, account, contract_instances['PrecompilesArythmeticTestsContract.sol'], a, b, a * b)

    # Test Division
    test_division(w3, account, contract_instances['PrecompilesMiscellaneousTestsContract.sol'], a, b, a / b)

    # Test Remainder
    test_remainder(w3, account, contract_instances['PrecompilesMiscellaneousTestsContract.sol'], a, b, a % b)

    # # Test Bitwise AND
    test_bitwise_and(w3, account, contract_instances['PrecompilesBitwiseTestsContract.sol'], a, b, a & b)

    # # Test Bitwise OR
    test_bitwise_or(w3, account, contract_instances['PrecompilesBitwiseTestsContract.sol'], a, b, a | b)

    # # Test Bitwise XOR
    test_bitwise_xor(w3, account, contract_instances['PrecompilesBitwiseTestsContract.sol'], a, b, a ^ b)

    # Test Bitwise Shift Left
    test_bitwise_shift_left(w3, account, contract_instances['PrecompilesShiftTestsContract.sol'], a, shift, (a << shift) & 0xFF, (a << shift) & 0xFFFF, (a << shift) & 0xFFFFFFFF, (a << shift) & 0xFFFFFFFFFFFFFFFF) # Calculate the result in 8, 16, 32, and 64 bit

    # Test Bitwise Shift Right
    test_bitwise_shift_right(w3, account, contract_instances['PrecompilesShiftTestsContract.sol'], a, shift, a >> shift)

    # Test Min
    test_min(w3, account, contract_instances['PrecompilesMinMaxTestsContract.sol'], a, b, min(a, b))

    # Test Max
    test_max(w3, account, contract_instances['PrecompilesMinMaxTestsContract.sol'], a, b, max(a, b))

    # Test Equality
    test_eq(w3, account, contract_instances['PrecompilesComparison2TestsContract.sol'], a, b, a == b)

    # Test Not Equal
    test_ne(w3, account, contract_instances['PrecompilesComparison2TestsContract.sol'], a, b, a != b)

    # Test Greater Than or Equal
    test_ge(w3, account, contract_instances['PrecompilesComparison2TestsContract.sol'], a, b, a >= b)

    # Test Greater Than
    test_gt(w3, account, contract_instances['PrecompilesComparison1TestsContract.sol'], a, b, a > b)

    # Test Less Than or Equal
    test_le(w3, account, contract_instances['PrecompilesComparison1TestsContract.sol'], a, b, a <= b)

    # Test Less Than
    test_lt(w3, account, contract_instances['PrecompilesComparison1TestsContract.sol'], a, b, a < b)

    # Test Mux
    test_mux(w3, account, contract_instances['PrecompilesMiscellaneousTestsContract.sol'], bit, a, b, a if bit == 0 else b)

    # Test Transfer
    test_transfer(w3, account, contract_instances['PrecompilesTransferTestsContract.sol'], a, b, b, a - b, b + b)
    
    # Test Transfer scalar
    test_transfer(w3, account, contract_instances['PrecompilesTransferScalarTestsContract.sol'], a, b, b, a - b, b + b)

    # Test Offboard_Onboard
    test_offboardOnboard(w3, account, contract_instances['PrecompilesMiscellaneousTestsContract.sol'], a, a)

    # test not
    test_not(w3, account, contract_instances['PrecompilesMiscellaneousTestsContract.sol'], bit, not bit)

    # test getUserKey
    test_getUserKey(w3, account, contract_instances['PrecompilesOffboardToUserKeyTestContract.sol'], a, a)

    # test random
    test_random(w3, account, contract_instances['PrecompilesMiscellaneous1TestsContract.sol'])

    # test random bounded bits
    test_randomBoundedBits(w3, account, contract_instances['PrecompilesMiscellaneous1TestsContract.sol'], numBits)


def runTestVectors(contract_instances, account, w3):

    print(f'\nTest Vector 0\n')

    #  test vector 0
    run_tests(contract_instances, account, w3, 10, 5, 2, False, 7)

    print(f'\nTest Vector 1\n')

    #  test vector 1
    run_tests(contract_instances, account, w3, 100, 50, 10, True, 8)

def main():
    print("Running tests...")
    contract_instances, account, w3 = setup()
    
    # Run the tests
    runTestVectors(contract_instances, account, w3)

if __name__ == "__main__":
    main()
