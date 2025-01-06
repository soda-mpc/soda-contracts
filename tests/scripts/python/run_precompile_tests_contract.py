import argparse
from datetime import datetime
import logging
import os
import sys
from time import sleep
sys.path.append('soda-sdk')
from python.crypto import generate_aes_key, write_aes_key, generate_rsa_keypair, recover_user_key, sign, decrypt, prepare_IT
from lib.python.soda_web3_helper import SodaWeb3Helper, LOCAL_PROVIDER_URL, REMOTE_HTTP_PROVIDER_URL
from web3.exceptions import TransactionNotFound
from eth_account import Account
import hashlib

# Path to the Solidity files
SOLIDITY_FILES = ['PrecompilesArythmeticTestsContract.sol',
                  'PrecompilesBitwiseTestsContract.sol', 
                  'PrecompilesComparison2TestsContract.sol', 
                  'PrecompilesMiscellaneousTestsContract.sol',
                  'PrecompilesMiscellaneous1TestsContract.sol',
                  'PrecompilesTransferTestsContract.sol', 
                  'PrecompilesTransferAllowanceTestsContract.sol', 
                  'PrecompilesTransferAllowanceScalarTestsContract.sol', 
                  'PrecompilesTransferScalarTestsContract.sol', 
                  'PrecompilesMinMaxTestsContract.sol', 
                  'PrecompilesShiftTestsContract.sol', 
                  'PrecompilesComparison1TestsContract.sol',
                  'PrecompilesOffboardToUserKeyTestContract.sol',
                  'PrecompilesCheckedFuncsTestsContract.sol',
                  'PrecompilesSHATestsContract.sol']
NONCE = 0

timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
OUTPUT_FILE = f'mpc_test_output.txt'

def setup(provider_url: str):
    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)

    # Compile the contracts
    for file_name in SOLIDITY_FILES:
        success = soda_helper.setup_contract("tests/contracts/" + file_name, file_name)
        if not success:
            print_error_to_file(f'Failed to set up the contract {file_name}')
            raise Exception("Failed to set up the contract")

    # Deploy the contract
    receipts = soda_helper.deploy_multi_contracts(SOLIDITY_FILES, constructor_args=[])
    
    if len(receipts) != len(SOLIDITY_FILES):
        print_error_to_file(f'Failed to deploy the contracts')
        raise Exception("Failed to deploy the contracts")

    global NONCE
    NONCE = soda_helper.get_current_nonce()

    return soda_helper

def print_with_timestamp(message):
    print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - {message}')

def print_error_to_file(message):
    with open(OUTPUT_FILE, "a") as output_file:
        print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - {message}', file=output_file, flush=True)

def execute_transaction_with_gas_estimation(name, soda_helper, contract, func_name, func_args=None):
    if func_args is None:
        func_args = []
    gas_estimate = soda_helper.estimate_gas(contract, func_name, func_args=func_args)
    print_with_timestamp(f'Estimated Gas: {gas_estimate}')
    global NONCE
    tx_hash = soda_helper.call_contract_transaction_async(contract, func_name, NONCE, func_args=func_args)
    NONCE += 1
    return tx_hash

def execute_transaction(name, soda_helper, contract, func_name, func_args=None):
    if func_args is None:
        func_args = []
    global NONCE
    tx_hash = soda_helper.call_contract_transaction_async(contract, func_name, NONCE, func_args=func_args)
    NONCE += 1
    return tx_hash

def check_expected_result(name, expected_result, result):
    if result == expected_result:
        print_with_timestamp(f'Test {name} succeeded: {result}')
    else:
        print_error_to_file(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')
        raise ValueError(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')

# Test functions
def test_addition(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("addition", soda_helper, contract, "addTest", func_args=[a, b])

def test_checked_addition(soda_helper, contract, a, b):
    return execute_transaction("checked addition", soda_helper, contract, "checkedAddTest", func_args=[a, b])

def test_subtraction(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("subtraction", soda_helper, contract, "subTest", func_args=[a, b])

def test_checked_subtraction(soda_helper, contract, a, b):
    return execute_transaction("checked subtraction", soda_helper, contract, "checkedSubTest", func_args=[a, b])

def test_multiplication(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("multiplication", soda_helper, contract, "mulTest", func_args=[a, b])

def test_checked_multiplication(soda_helper, contract, a, b):
    return execute_transaction("checked multiplication", soda_helper, contract, "checkedMulTest", func_args=[a, b])

def test_division(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("division", soda_helper, contract, "divTest", func_args=[a, b])

def test_remainder(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("reminder", soda_helper, contract, "remTest", func_args=[a, b])

def test_bitwise_and(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("bitwise and", soda_helper, contract, "andTest", func_args=[a, b])

def test_bitwise_or(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("bitwise or", soda_helper, contract, "orTest", func_args=[a, b])

def test_bitwise_xor(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("bitwise xor", soda_helper, contract, "xorTest", func_args=[a, b])

def test_bitwise_shift_left(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("bitwise shift left", soda_helper, contract, "shlTest", func_args=[a, b])

def test_bitwise_shift_right(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("bitwise shift right", soda_helper, contract, "shrTest", func_args=[a, b])

def test_min(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("min", soda_helper, contract, "minTest", func_args=[a, b])

def test_max(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("max", soda_helper, contract, "maxTest", func_args=[a, b])

def test_eq(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("equality", soda_helper, contract, "eqTest", func_args=[a, b])

def test_ne(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("not equal", soda_helper, contract, "neTest", func_args=[a, b])

def test_ge(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("greater than or equal", soda_helper, contract, "geTest", func_args=[a, b])

def test_gt(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("greater than", soda_helper, contract, "gtTest", func_args=[a, b])

def test_le(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("less than or equal", soda_helper, contract, "leTest", func_args=[a, b])

def test_lt(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("less than", soda_helper, contract, "ltTest", func_args=[a, b])

def test_mux(soda_helper, contract, selectionBit, a, b):
    return execute_transaction_with_gas_estimation("mux", soda_helper, contract, "muxTest", func_args=[selectionBit, a, b])

def test_transfer(soda_helper, contract, a, b, amount):
    return execute_transaction_with_gas_estimation("transfer", soda_helper, contract, "transferTest", func_args=[a, b, amount])

def test_transfer_allowance(soda_helper, contract, a, b, amount, allowance):
    return execute_transaction_with_gas_estimation("transfer with allowance", soda_helper, contract, "transferWithAllowanceTest", func_args=[a, b, amount, allowance])

def test_offboardOnboard(soda_helper, contract, a):
    return execute_transaction_with_gas_estimation("offboard_Onboard", soda_helper, contract, "offboardOnboardTest", func_args=[a, a, a, a])

def test_not(soda_helper, contract, bit):
    return execute_transaction_with_gas_estimation("not", soda_helper, contract, "notTest", func_args=[bit])
    
 
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

def test_getUserKey(soda_helper, contract, a, public_key):
    signing_key = os.environ.get('SIGNING_KEY')
    signature = sign(public_key, bytes.fromhex(signing_key[2:]))
    execute_transaction_with_gas_estimation("get user key", soda_helper, contract, "userKeyTest", func_args=[public_key, signature])

    return execute_transaction_with_gas_estimation("offboard to user", soda_helper, contract, "offboardToUserTest", func_args=[a, soda_helper.get_account().address])

last_random_result = 0
last_random_bounded_result = 0

def test_random(soda_helper, contract):
    return execute_transaction("random", soda_helper, contract, "randomTest")

def test_randomBoundedBits(soda_helper, contract, numBits):
    return execute_transaction("random bounded", soda_helper, contract, "randomBoundedTest", func_args=[numBits])

def test_boolean(soda_helper, contract, bool_a, bool_b, bit):
    return execute_transaction_with_gas_estimation("boolean tests", soda_helper, contract, "booleanTest", func_args=[bool_a, bool_b, bit])

def get_function_signature(function_abi):
    # Extract the input types from the ABI
    input_types = ','.join([param['type'] for param in function_abi.get('inputs', [])])

    # Generate the function signature
    return f"{function_abi['name']}({input_types})"

def test_validate_ciphertext(soda_helper, contract_str, a):
    user_key_hex = os.environ.get('USER_KEY')
    user_aes_key = bytes.fromhex(user_key_hex)  
    sign_key = os.environ.get('SIGNING_KEY')
    
    # In order to generate the input text, we need to use some data of the function. 
    # For example, the address of the user, the address of the contract and also the function signature.
    # To simplify the process of obtaining the function signature, we use a dummy function with placeholder inputs.
    # After the signature is generated, we call prepare input text function and get the input text to use in the real function.
    dummyCT = 0
    dummySignature = bytes(65)
    contract = soda_helper.get_contract(contract_str)
    function = contract.functions.validateCiphertextTest(dummyCT, dummyCT, dummyCT, dummyCT, dummySignature)
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(a, user_aes_key, Account.from_key(sign_key), contract, func_sig, bytes.fromhex(sign_key[2:]))
    return execute_transaction_with_gas_estimation("validate ciphertext", soda_helper, contract_str, "validateCiphertextTest", func_args=[ct, ct, ct, ct, signature])


def test_validate_ciphertext_eip191(soda_helper, contract_str, a):
    user_key_hex = os.environ.get('USER_KEY')
    user_aes_key = bytes.fromhex(user_key_hex)
    sign_key = os.environ.get('SIGNING_KEY')

    # In order to generate the input text, we need to use some data of the function.
    # For example, the address of the user, the address of the contract and also the function signature.
    # To simplify the process of obtaining the function signature, we use a dummy function with placeholder inputs.
    # After the signature is generated, we call prepare input text function and get the input text to use in the real function.
    dummyCT = 0
    dummySignature = bytes(65)
    contract = soda_helper.get_contract(contract_str)
    function = contract.functions.validateCiphertextTest(dummyCT, dummyCT, dummyCT, dummyCT, dummySignature)
    func_sig = get_function_signature(function.abi)  # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(a, user_aes_key, Account.from_key(sign_key), contract, func_sig,
                               bytes.fromhex(sign_key[2:]), eip191=True)
    return execute_transaction_with_gas_estimation("validate ciphertext eip191", soda_helper, contract_str,
                                                   "validateCiphertextTest", func_args=[ct, ct, ct, ct, signature])

def test_sha256(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("sha256Fixed432BitInput", soda_helper, contract, "sha256Fixed432BitInputTest", func_args=[a, b, b, soda_helper.account.address, 0, 0])


def checkResults(soda_helper, expected_results, private_key):
    
    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getAddResult")
    check_expected_result("addition", expected_results["addition"], result)

    result = soda_helper.call_contract_view('PrecompilesCheckedFuncsTestsContract.sol', "getAddResult")
    check_expected_result("checked_addition", expected_results["checked_addition"], result)

    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getSubResult")
    check_expected_result("subtract", expected_results["subtract"], result)

    result = soda_helper.call_contract_view('PrecompilesCheckedFuncsTestsContract.sol', "getSubResult")
    check_expected_result("checked_subtract", expected_results["checked_subtract"], result)

    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getMulResult")
    check_expected_result("multiplication", expected_results["multiplication"], result)

    result = soda_helper.call_contract_view('PrecompilesCheckedFuncsTestsContract.sol', "getMulResult")
    check_expected_result("checked_multiplication", expected_results["multiplication"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getDivResult")
    check_expected_result("division", expected_results["division"], result)
    
    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getRemResult")
    check_expected_result("reminder", expected_results["reminder"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getMuxResult")
    check_expected_result("mux", expected_results["mux"], result)

    result = soda_helper.call_contract_view('PrecompilesOffboardToUserKeyTestContract.sol', "getOnboardOffboardResult")
    check_expected_result("onboard_offboard", expected_results["onboard_offboard"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getBoolResult")
    check_expected_result("not", expected_results["not"], result)

    result = soda_helper.call_contract_view('PrecompilesBitwiseTestsContract.sol', "getAndResult")
    check_expected_result("and", expected_results["and"], result)
    
    result = soda_helper.call_contract_view('PrecompilesBitwiseTestsContract.sol', "getOrResult")
    check_expected_result("or", expected_results["or"], result)
    
    result = soda_helper.call_contract_view('PrecompilesBitwiseTestsContract.sol', "getXorResult")
    check_expected_result("xor", expected_results["xor"], result)

    result8, result16, result32, result64 = soda_helper.call_contract_view('PrecompilesShiftTestsContract.sol', "getAllShiftResults")
    check_expected_result("bitwise shift left 8", expected_results["shift_left8"], result8)
    check_expected_result("bitwise shift left 16", expected_results["shift_left16"], result16)
    check_expected_result("bitwise shift left 32", expected_results["shift_left32"], result32)
    check_expected_result("bitwise shift left 64", expected_results["shift_left64"], result64)

    result = soda_helper.call_contract_view('PrecompilesShiftTestsContract.sol', "getResult")
    check_expected_result("bitwise shift right", expected_results["shift_right"], result)

    result = soda_helper.call_contract_view('PrecompilesMinMaxTestsContract.sol', "getMinResult")
    check_expected_result("min", expected_results["min"], result)

    result = soda_helper.call_contract_view('PrecompilesMinMaxTestsContract.sol', "getMaxResult")
    check_expected_result("max", expected_results["max"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison2TestsContract.sol', "getEqResult")
    check_expected_result("eq", expected_results["eq"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison2TestsContract.sol', "getNeResult")
    check_expected_result("ne", expected_results["ne"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison2TestsContract.sol', "getGeResult")
    check_expected_result("ge", expected_results["ge"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison1TestsContract.sol', "getGtResult")
    check_expected_result("gt", expected_results["gt"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison1TestsContract.sol', "getLeResult")
    check_expected_result("le", expected_results["le"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison1TestsContract.sol', "getLtResult")
    check_expected_result("lt", expected_results["lt"], result)
    
    new_a, new_b, res = soda_helper.call_contract_view('PrecompilesTransferTestsContract.sol', "getResults")
    if not res:
        print_error_to_file(f'Test transfer failed.')
        raise Exception(f'Test transfer Failed.')
    
    check_expected_result("transfer", expected_results["transfer_a"], new_a)
    check_expected_result("transfer", expected_results["transfer_b"], new_b)
    
    new_a, new_b, res = soda_helper.call_contract_view('PrecompilesTransferScalarTestsContract.sol', "getResults")
    if not res:
        print_error_to_file(f'Test transfer scalar failed.')
        raise Exception(f'Test transfer scalar failed.')
    
    check_expected_result("transfer scalar", expected_results["transfer_a"], new_a)
    check_expected_result("transfer scalar", expected_results["transfer_b"], new_b)

    new_a, new_b, res, allowance = soda_helper.call_contract_view('PrecompilesTransferAllowanceTestsContract.sol', "getResults")
    if not res:
        print_error_to_file(f'Test transfer with allowance failed.')
        raise Exception(f'Test transfer with allowance failed.')
    
    check_expected_result("transfer_allowance", expected_results["transfer_a"], new_a)
    check_expected_result("transfer_allowance", expected_results["transfer_b"], new_b)
    check_expected_result("transfer_allowance", expected_results["transfer_allowance"], allowance)

    new_a, new_b, res, allowance = soda_helper.call_contract_view('PrecompilesTransferAllowanceTestsContract.sol', "getResults")
    if not res:
        print_error_to_file(f'Test transfer with allowance scalar failed.')
        raise Exception(f'Test transfer with allowance scalar failed.')
    
    check_expected_result("transfer_allowance_scalar", expected_results["transfer_a"], new_a)
    check_expected_result("transfer_allowance_scalar", expected_results["transfer_b"], new_b)
    check_expected_result("transfer_allowance_scalar", expected_results["transfer_allowance"], allowance)

    andRes, orRes, xorRes, notRes, eqRes, neqRes, muxRes, onboardRes = soda_helper.call_contract_view('PrecompilesMiscellaneous1TestsContract.sol', "getBooleanResults")
    check_expected_result("boolean_and", expected_results["boolean_and"], andRes)
    check_expected_result("boolean_or", expected_results["boolean_or"], orRes)
    check_expected_result("boolean_xor", expected_results["boolean_xor"], xorRes)
    check_expected_result("boolean_not", expected_results["boolean_not"], notRes)
    check_expected_result("boolean_equal", expected_results["boolean_equal"], eqRes)
    check_expected_result("boolean_notEqual", expected_results["boolean_notEqual"], neqRes)
    check_expected_result("boolean_mux", expected_results["boolean_mux"], muxRes)
    check_expected_result("boolean_onboard_offboard", expected_results["boolean_onboard_offboard"], onboardRes)

    (encryptedKey0, encryptedKey1) = soda_helper.call_contract_view("PrecompilesOffboardToUserKeyTestContract.sol", "getUserKeyShares")
    decrypted_aes_key = recover_user_key(private_key, encryptedKey0, encryptedKey1)

    ct8, ct16, ct32, ct64 = soda_helper.call_contract_view("PrecompilesOffboardToUserKeyTestContract.sol", "getCTs")
    checkCt(ct8, decrypted_aes_key, expected_results["offboard_user"])
    checkCt(ct16, decrypted_aes_key, expected_results["offboard_user"])
    checkCt(ct32, decrypted_aes_key, expected_results["offboard_user"])
    checkCt(ct64, decrypted_aes_key, expected_results["offboard_user"])

    global last_random_result  # Use the global keyword to use and modify the global variable
    result = soda_helper.call_contract_view("PrecompilesMiscellaneous1TestsContract.sol", "getRandom")
    if result != last_random_result:
        print_with_timestamp(f'Test Random succeeded: {result}')
        last_random_result = result
    else:
        print_error_to_file(f'Test Random failed. {result}')
        raise Exception(f'Test Random failed. {result}')

    # global last_random_bounded_result
    # result = soda_helper.call_contract_view("PrecompilesMiscellaneous1TestsContract.sol", "getRandomBounded")
    # if result != last_random_bounded_result:
    #     print_with_timestamp(f'Test RandomBoundedBits succeeded: {result}')
    #     last_random_bounded_result = result
    # else:
    #     print_error_to_file(f'Test RandomBoundedBits failed. {result}')
    #     raise Exception(f'Test RandomBoundedBits failed. {result}')

    result = soda_helper.call_contract_view('PrecompilesMiscellaneous1TestsContract.sol', "getValidateCiphertextResult")
    check_expected_result("validate_ciphertext", expected_results["validate_ciphertext"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneous1TestsContract.sol', "getValidateCiphertextResult")
    check_expected_result("validate_ciphertext_eip191", expected_results["validate_ciphertext_eip191"], result)

    result = soda_helper.call_contract_view('PrecompilesSHATestsContract.sol', "getSHAOutput")
    check_expected_result("SHA256Fixed43bitInput", expected_results["SHA256Fixed43bitInput"], result)

# Main test function
def run_tests(soda_helper, a, b, shift, bit, numBits, bool_a, bool_b, allowance, check_results):
    expected_results = {}
    tx_hashes = {}

    # Test Addition
    print_with_timestamp("Run addition test...")
    tx_hash = test_addition(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "addition"
    expected_results["addition"] = a+b

    # Test Checked Addition
    print_with_timestamp("Run checked addition test...")
    tx_hash = test_checked_addition(soda_helper, 'PrecompilesCheckedFuncsTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "checked_addition"
    expected_results["checked_addition"] = a+b
    
    # Test Subtraction
    print_with_timestamp("Run subtraction test...")
    tx_hash = test_subtraction(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "subtract"
    expected_results["subtract"] = a-b

    # Test Checked Subtraction
    print_with_timestamp("Run checked subtraction test...")
    tx_hash = test_checked_subtraction(soda_helper, 'PrecompilesCheckedFuncsTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "checked_subtract"
    expected_results["checked_subtract"] = a-b

    # Test Multiplication
    print_with_timestamp("Run multiplication test...")
    tx_hash = test_multiplication(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "multiplication"
    expected_results["multiplication"] = a*b

    # Test checked Multiplication
    print_with_timestamp("Run checked multiplication test...")
    tx_hash = test_checked_multiplication(soda_helper, 'PrecompilesCheckedFuncsTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "checked_multiplication"

    # Test Division
    print_with_timestamp("Run division test...")
    tx_hash = test_division(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "division"
    expected_results["division"] = a/b

    # Test Remainder
    print_with_timestamp("Run remainder test...")
    tx_hash = test_remainder(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "reminder"
    expected_results["reminder"] = a%b

    # Test Mux
    print_with_timestamp("Run mux test...")
    tx_hash = test_mux(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', bit, a, b)
    tx_hashes[tx_hash] = "mux"
    expected_results["mux"] = a if bit == 0 else b

    # Test Offboard_Onboard
    print_with_timestamp("Run offboard_Onboard test...")
    tx_hash = test_offboardOnboard(soda_helper, 'PrecompilesOffboardToUserKeyTestContract.sol', a)
    tx_hashes[tx_hash] = "onboard_offboard"
    expected_results["onboard_offboard"] = a

    # test Not
    print_with_timestamp("Run not test...")
    tx_hash = test_not(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', bit)
    tx_hashes[tx_hash] = "not"
    expected_results["not"] = not bit

    # Test Bitwise AND
    print_with_timestamp("Run and test...")
    tx_hash = test_bitwise_and(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "and"
    expected_results["and"] = a & b

    # Test Bitwise OR
    print_with_timestamp("Run or test...")
    tx_hash = test_bitwise_or(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "or"
    expected_results["or"] = a | b

    # Test Bitwise XOR
    print_with_timestamp("Run xor test...")
    tx_hash = test_bitwise_xor(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "xor"
    expected_results["xor"] = a ^ b

    # Test Bitwise Shift Left
    print_with_timestamp("Run shift left test...")
    tx_hash = test_bitwise_shift_left(soda_helper, 'PrecompilesShiftTestsContract.sol', a, shift) 
    tx_hashes[tx_hash] = "shl"
    # Calculate the result in 8, 16, 32, and 64 bit
    expected_results["shift_left8"] = (a << shift) & 0xFF
    expected_results["shift_left16"] = (a << shift) & 0xFFFF
    expected_results["shift_left32"] = (a << shift) & 0xFFFFFFFF
    expected_results["shift_left64"] = (a << shift) & 0xFFFFFFFFFFFFFFFF

    # Test Bitwise Shift Right
    print_with_timestamp("Run shift right test...")
    tx_hash = test_bitwise_shift_right(soda_helper, 'PrecompilesShiftTestsContract.sol', a, shift)
    tx_hashes[tx_hash] = "shr"
    expected_results["shift_right"] = a >> shift

    # Test Min
    print_with_timestamp("Run min test...")
    tx_hash = test_min(soda_helper, 'PrecompilesMinMaxTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "min"
    expected_results["min"] = min(a, b)

    # Test Max
    print_with_timestamp("Run max test...")
    tx_hash = test_max(soda_helper, 'PrecompilesMinMaxTestsContract.sol', a, b)
    tx_hashes[tx_hash] = "max"
    expected_results["max"] = max(a, b)

    # Test Equality
    print_with_timestamp("Run equality test...")
    tx_hash = test_eq(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b)
    tx_hashes[tx_hash] = "eq"
    expected_results["eq"] = (a == b)

    # Test Not Equal
    print_with_timestamp("Run not equal test...")
    tx_hash = test_ne(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b)
    tx_hashes[tx_hash] = "ne"
    expected_results["ne"] = (a != b)

    # Test Greater Than or Equal
    print_with_timestamp("Run greater than or equal test...")
    tx_hash = test_ge(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b)
    tx_hashes[tx_hash] = "ge"
    expected_results["ge"] = (a >= b)

    # Test Greater Than
    print_with_timestamp("Run greater than test...")
    tx_hash = test_gt(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b)
    tx_hashes[tx_hash] = "gt"
    expected_results["gt"] = (a > b)

    # Test Less Than or Equal
    print_with_timestamp("Run less than or equal test...")
    tx_hash = test_le(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b)
    tx_hashes[tx_hash] = "le"
    expected_results["le"] = (a <= b)

    # Test Less Than
    print_with_timestamp("Run less than test...")
    tx_hash = test_lt(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b)
    tx_hashes[tx_hash] = "lt"
    expected_results["lt"] = (a < b)

    # Test Transfer
    print_with_timestamp("Run transfer test...")
    tx_hash = test_transfer(soda_helper, 'PrecompilesTransferTestsContract.sol', a, b, b)
    tx_hashes[tx_hash] = "transfer"
    expected_results["transfer_a"] = a - b
    expected_results["transfer_b"] = b + b
    
    # Test Transfer scalar
    print_with_timestamp("Run transfer scalar test...")
    tx_hash = test_transfer(soda_helper, 'PrecompilesTransferScalarTestsContract.sol', a, b, b)
    tx_hashes[tx_hash] = "transfer_scalar"

    # Test Transfer with allowance
    print_with_timestamp("Run transfer with allowance test...")
    tx_hash = test_transfer_allowance(soda_helper, 'PrecompilesTransferAllowanceTestsContract.sol', a, b, b, allowance)
    tx_hashes[tx_hash] = "transfer_allowance"
    expected_results["transfer_allowance"] = allowance - b

    # Test Transfer with allowance scalar
    print_with_timestamp("Run transfer with allowance scalar test...")
    tx_hash = test_transfer_allowance(soda_helper, 'PrecompilesTransferAllowanceScalarTestsContract.sol', a, b, b, allowance)
    tx_hashes[tx_hash] = "transfer_allowance_scalar"

    # Test boolean functions
    print_with_timestamp("Run Boolean functions test...")
    tx_hash = test_boolean(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', bool_a, bool_b, bit)
    tx_hashes[tx_hash] = "boolean"
    expected_results["boolean_and"] = bool_a and bool_b
    expected_results["boolean_or"] = bool_a or bool_b
    expected_results["boolean_xor"] = bool_a ^ bool_b
    expected_results["boolean_not"] = not bool_a
    expected_results["boolean_equal"] = bool_a == bool_b
    expected_results["boolean_notEqual"] = bool_a != bool_b
    expected_results["boolean_mux"] = bool_b if bit else bool_a
    expected_results["boolean_onboard_offboard"] = bool_a

    # Test getUserKey
    print_with_timestamp("Run get user key test...")
    private_key, public_key = generate_rsa_keypair()
    tx_hash = test_getUserKey(soda_helper, 'PrecompilesOffboardToUserKeyTestContract.sol', a, public_key)
    tx_hashes[tx_hash] = "offboard_user"
    expected_results["offboard_user"] = a

    # Test Validate Ciphertext
    print_with_timestamp("Run validate ciphertext test...")
    tx_hash = test_validate_ciphertext(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', a)
    tx_hashes[tx_hash] = "validate_ciphertext"
    expected_results["validate_ciphertext"] = a

    # Test Validate Ciphertext
    print_with_timestamp("Run validate ciphertext eip191 test...")
    tx_hash = test_validate_ciphertext_eip191(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', a)
    tx_hashes[tx_hash] = "validate_ciphertext_eip191"
    expected_results["validate_ciphertext_eip191"] = a

    # test random
    print_with_timestamp("Run random test...")
    tx_hash = test_random(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol')
    tx_hashes[tx_hash] = "random"

    # test random bounded bits
    print_with_timestamp("Run random Bounded Bits test...")
    tx_hash = test_randomBoundedBits(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', numBits)
    tx_hashes[tx_hash] = "random_bounded"

    # test SHA256Fixed43bitInput
    print_with_timestamp("Run SHA256 with fixed 432 bit input test...")
    tx_hash = test_sha256(soda_helper, 'PrecompilesSHATestsContract.sol', a, b)
    tx_hashes[tx_hash] = "SHA256Fixed43bitInput"
    aBytes = a.to_bytes(8, byteorder='big')
    bBytes = b.to_bytes(8, byteorder='big')
    zero64 = bytes(8) # Represents 64 bits of zeros
    zero16 = bytes(2) # Represents 16 bits of zeros
    address_bytes = bytes.fromhex(soda_helper.account.address[2:])
    data = aBytes + bBytes + bBytes + address_bytes + zero64 + zero16
    hash_object = hashlib.sha256(data)
    expected_result = hash_object.digest()
    expected_results["SHA256Fixed43bitInput"] = expected_result
    
    if not check_results:
        return
    
    tx_receipts = set()
    print_with_timestamp(f"Wait for transaction receipts...")
    while len(tx_receipts) < len(tx_hashes):
        for h, name in tx_hashes.items():
            if h in tx_receipts:
                continue
            try:
                r = soda_helper.web3.eth.get_transaction_receipt(h.hex())
                if r is not None:
                    if r.status == 0:
                        print_error_to_file(f'Transaction {name} reverted.')
                        raise Exception(f'Transaction {name} reverted.')
                tx_receipts.add(h)
            except TransactionNotFound as e:
                pass
        sleep(1)

    checkResults(soda_helper, expected_results, private_key)

def runTestVectors(soda_helper, check_results):

    print_with_timestamp(f'\nTest Vector 0\n')

    #  test vector 0
    run_tests(soda_helper, 10, 5, 2, False, 7, True, False, 7, check_results)

    print_with_timestamp(f'\nTest Vector 1\n')

    #  test vector 1
    run_tests(soda_helper, 100, 2, 10, True, 8, False, False, 80, check_results)


def main(provider_url: str, check_results: bool):

    print_with_timestamp("Running tests...")
    soda_helper = setup(provider_url)

    # Run the tests
    runTestVectors(soda_helper, check_results)

def parse_url_parameter():
    parser = argparse.ArgumentParser(description='Get URL')
    parser.add_argument('provider_url', type=str, help='The provider url')
    parser.add_argument("--output_file", help="The output file to write the results to", default="mpc_test_output.txt")
    parser.add_argument("--check_results", help="Indicates whether to check the results", default="True")

    args = parser.parse_args()
    print(f'Provider URL: {args.provider_url}')
    if args.check_results == "False":  
        check_results = False
    else:
        check_results = True
    print(f'Check results: {check_results}')


    global OUTPUT_FILE
    OUTPUT_FILE = f'logs/{args.output_file}'

    if not args.provider_url:
        raise Exception("No URL provided")
    if args.provider_url == "Local":
        return LOCAL_PROVIDER_URL, check_results
    elif args.provider_url == "Remote":
        return REMOTE_HTTP_PROVIDER_URL, check_results
    else:
        return args.provider_url, check_results
    
if __name__ == "__main__":
    url, check_results = parse_url_parameter()
    if (url is not None):
        try:
            main(url, check_results)
        except Exception as e:
            logging.error("An error occurred: %s", e)
            raise e
