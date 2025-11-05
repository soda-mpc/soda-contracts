import argparse
from datetime import datetime
import logging
import os
from time import sleep
import requests
from eth_abi import decode
from soda_python_sdk import generate_rsa_keypair, recover_user_key, sign, decrypt, prepare_IT, prepare_IT_256
from lib.python.soda_web3_helper import SodaWeb3Helper, LOCAL_PROVIDER_URL, REMOTE_HTTP_PROVIDER_URL
from web3.exceptions import TransactionNotFound
from eth_account import Account
import hashlib
import re

# Path to the Solidity files
SOLIDITY_FILES = ['PrecompilesArythmeticTestsContract.sol',
                  'PrecompilesMul128_256TestsContract.sol',
                  'PrecompilesDivRem128_256TestsContract.sol',
                  'PrecompilesBitwiseTestsContract.sol', 
                  'PrecompilesBitwise2TestsContract.sol', 
                  'PrecompilesComparison2TestsContract.sol', 
                  'PrecompilesComparison3TestsContract.sol', 
                  'PrecompilesMiscellaneousTestsContract.sol',
                  'PrecompilesMiscellaneous1TestsContract.sol',
                  'PrecompilesTransferTestsContract.sol', 
                  'PrecompilesTransferAllowanceTestsContract.sol',
                  'PrecompilesTransferAllowance128_256bitTestsContract.sol',
                  'PrecompilesTransferAllowanceScalarTestsContract.sol', 
                  'PrecompilesTransferAllowanceScalar256BitTestsContract.sol',
                  'PrecompilesTransferScalarTestsContract.sol',
                  'PrecompilesMinMaxTestsContract.sol', 
                  'PrecompilesShiftTestsContract.sol', 
                  'PrecompilesComparison1TestsContract.sol',
                  'PrecompilesOffboardToUserKeyTestContract.sol',
                  'PrecompilesCheckedFuncsTestsContract.sol',
                  'PrecompilesCheckedWithOverflowFuncsTestsContract.sol',
                  'PrecompilesCheckedWithOverflowFuncs1TestsContract.sol',
                  'PrecompilesSHATestsContract.sol']
AES_BLOCK_SIZE = 16
NONCE = 0
MAX_SLEEP_TIME = 600
MAX_UINT_8 = 255
MAX_UINT_16 = 65535
MAX_UINT_32 = 4294967295
MAX_UINT_64 = 18446744073709551615
MAX_UINT_128 = 340282366920938463463374607431768211455
MAX_UINT_256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935

timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
OUTPUT_FILE = f'mpc_test_output.txt'

transaction_log_file = f'logs/transactions_log.txt'

def setup(provider_url: str):
    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)

    # Compile the contracts
    for file_name in SOLIDITY_FILES:
        success = soda_helper.setup_contract("tests/contracts/" + file_name, file_name)
        if not success:
            print_error_to_file(f'Failed to set up the contract {file_name}')
            raise Exception("Failed to set up the contract")

    try:
        # Deploy the contract
        receipts = soda_helper.deploy_multi_contracts(SOLIDITY_FILES, constructor_args=[])
    except Exception as e:
        print_error_to_file(f'Failed to deploy the contracts')
        raise Exception("Failed to deploy the contracts")
    
    if len(receipts) != len(SOLIDITY_FILES):
        print_error_to_file(f'Failed to deploy the contracts')
        raise Exception("Failed to deploy the contracts")
    
    for receipt in receipts:
        message = f'Deploy contract resulted in transaction hash {receipt.transactionHash.hex()}'
        with open(transaction_log_file, "a") as output_file:
            print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - {message}', file=output_file, flush=True)

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
    return execute_transaction_with_gas_estimation("checked addition", soda_helper, contract, "checkedAddTest", func_args=[a, b])

def test_checked_addition_with_overflow_bit(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("checked addition with overflow bit", soda_helper, contract, "checkedAddWithOverflowBitTest", func_args=[a, b])

# Test Checked Addition that should overflow
def test_checked_addition_overflow(soda_helper, contract, a, b, a16, b16, a32, b32, a64, b64, a128, b128, a256, b256):
    return execute_transaction_with_gas_estimation("checked addition overflow", soda_helper, contract, "checkedAddOverflowTest", func_args=[a, b, a16, b16, a32, b32, a64, b64, a128, b128, a256, b256])

def test_subtraction(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("subtraction", soda_helper, contract, "subTest", func_args=[a, b])

def test_checked_subtraction(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("checked subtraction", soda_helper, contract, "checkedSubTest", func_args=[a, b])

def test_checked_subtraction_with_overflow_bit(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("checked subtraction with overflow bit", soda_helper, contract, "checkedSubWithOverflowBitTest", func_args=[a, b])

# Test Checked Subtraction that should overflow
def test_checked_subtraction_overflow(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("checked subtraction overflow", soda_helper, contract, "checkedSubOverflowTest", func_args=[a, b])

def test_multiplication(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("multiplication", soda_helper, contract, "mulTest", func_args=[a, b])

def test_checked_multiplication(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("checked multiplication", soda_helper, contract, "checkedMulTest", func_args=[a, b])

def test_checked_multiplication_with_overflow_bit(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("checked multiplication with overflow bit", soda_helper, contract, "checkedMulWithOverflowBitTest", func_args=[a, b])

def test_checked_multiplication_with_overflow_bit_128_256(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("checked multiplication with overflow bit 128-256", soda_helper, contract, "checkedMulWithOverflowBit128_256Test", func_args=[a, b])

# Test Checked Multiplication that should overflow
def test_checked_multiplication_overflow(soda_helper, contract, a, b, a16, b16, a32, b32, a64, b64, a128, b128, a256, b256):
    return execute_transaction_with_gas_estimation("checked multiplication overflow", soda_helper, contract, "checkedMulOverflowTest", func_args=[a, b, a16, b16, a32, b32, a64, b64, a128, b128, a256, b256])

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
    return execute_transaction_with_gas_estimation("offboard_Onboard", soda_helper, contract, "offboardOnboardTest", func_args=[a, a, a, a, a, a])

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
    check_expected_result("offboardToUser", expected_result, x)

def checkCt256(ct1, ct2, decrypted_aes_key, expected_result):
    # Convert ct to bytes (big-endian)
    byte_array1 = ct1.to_bytes(AES_BLOCK_SIZE*2, byteorder='big')
    byte_array2 = ct2.to_bytes(AES_BLOCK_SIZE*2, byteorder='big')

    # Split ct into two 128-bit arrays r and cipher
    cipher1 = byte_array1[:AES_BLOCK_SIZE]
    r1 = byte_array1[AES_BLOCK_SIZE:]
    cipher2 = byte_array2[:AES_BLOCK_SIZE]
    r2 = byte_array2[AES_BLOCK_SIZE:]

    # Decrypt the cipher
    decrypted_message = decrypt(decrypted_aes_key, r1, cipher1, r2, cipher2)

    # Print the decrypted cipher
    x = int.from_bytes(decrypted_message, 'big')
    check_expected_result("offboardToUser256", expected_result, x)

def print_tx_data(tx_hash, test_name, contract_name, func_name):
    message = f'Transaction hash {tx_hash.hex()} resulted from test "{test_name}" using function "{func_name}" on contract "{contract_name}"'
    with open(transaction_log_file, "a") as output_file:
        print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - {message}', file=output_file, flush=True)

def trace_transaction(tx_hash, provider_url):
    # Convert HexBytes to string if needed
    if hasattr(tx_hash, 'hex'):
        tx_hash_str = tx_hash.hex()
    else:
        tx_hash_str = str(tx_hash)
    
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [
            tx_hash_str,
            { "tracer": "callTracer" }
        ],
        "id": 1
    }
    response = requests.post(provider_url, json=payload)
    response.raise_for_status()
    result = response.json()
    if "error" in result:
        raise Exception(f"RPC Error: {result['error']}")
    return result["result"]

def extract_output(trace):
    if "output" in trace:
        return trace["output"]
    return None

def extract_last_call(trace):
    """Extract the last call from the trace to show what proved the result"""
    if "calls" in trace and trace["calls"]:
        return trace["calls"][-1]  # Return the last call
    return None

def decode_uint8_output(output_hex):
    # Strip 0x and decode using eth_abi
    output_bytes = bytes.fromhex(output_hex[2:])
    return decode(["uint8"], output_bytes)[0]

def verify_trace_result(tx_hash, operation_name, inputs, expected_result, operation_func=None, provider_url=None):
    """
    General trace verification function
    
    Args:
        tx_hash: Transaction hash to trace
        operation_name: Name of the operation being tested
        inputs: Dictionary of input values
        expected_result: Expected result value
        operation_func: Optional function to calculate expected result from inputs
    """
    print(f"🔍 Checking {operation_name} tx: {tx_hash} with inputs: {inputs}")
    try:
        trace = trace_transaction(tx_hash, provider_url)
        output_hex = extract_output(trace)
        if not output_hex:
            print("❌ No output found in trace.")
            return False

        decoded_result = decode_uint8_output(output_hex)
        
        # Calculate expected result if operation_func is provided
        if operation_func:
            calculated_expected = operation_func(**inputs)
            expected_result = calculated_expected
        
        print(f"🔢 Output from trace: {decoded_result}")
        print(f"✅ Expected result: {expected_result}")

        if decoded_result == expected_result:
            print(f"🎉 {operation_name} test passed: result matches expected.")
            
            # Show the last call that proves the result
            last_call = extract_last_call(trace)
            if last_call:
                print(f"📋 Last call that proved the result:")
                print(f"   Type: {last_call.get('type', 'unknown')}")
                print(f"   From: {last_call.get('from', 'unknown')}")
                print(f"   To: {last_call.get('to', 'unknown')}")
                if 'value' in last_call:
                    print(f"   Value: {last_call.get('value', 'unknown')}")
                if 'input' in last_call:
                    print(f"   Input: {last_call.get('input', 'unknown')}")
                if 'output' in last_call:
                    print(f"   Output: {last_call.get('output', 'unknown')}")
            else:
                print(f"📋 No detailed call information available")
            
            return True
        else:
            print(f"❌ {operation_name} test failed: result does not match expected.")
            return False
    except Exception as e:
        print(f"❌ Error during {operation_name} trace verification: {e}")
        return False


def verify_trace_for_operation(soda_helper, tx_hashes, operation_name, inputs, expected_result, operation_func, provider_url):
    """Verify trace result for a specific operation"""
    print_with_timestamp(f"Verifying {operation_name} result using transaction trace...")
    
    # Find the transaction hash for this operation
    operation_tx_hash = None
    for tx_hash, test_name in tx_hashes.items():
        if test_name == operation_name:
            operation_tx_hash = tx_hash
            break
    
    if operation_tx_hash:
        trace_success = verify_trace_result(
            operation_tx_hash,
            operation_name,
            inputs,
            expected_result,
            operation_func,
            provider_url
        )
        if not trace_success:
            print_error_to_file(f"{operation_name} trace verification failed")
            raise Exception(f"{operation_name} trace verification failed")
    else:
        print_with_timestamp(f"Warning: No transaction hash found for {operation_name}")

def debug_trace_block(block_number, provider_url):
    """Trace an entire block and return all transaction traces"""
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_traceBlockByNumber",
        "params": [hex(block_number), {"tracer": "callTracer"}],
        "id": 1,
    }
    response = requests.post(provider_url, json=payload)
    response.raise_for_status()
    data = response.json()

    if "error" in data:
        raise Exception(f"RPC error: {data['error']}")

    if "result" not in data or data["result"] is None:
        raise Exception("Missing or null block trace result")

    return data["result"]


def trace_block_for_operation(soda_helper, tx_hashes, operation_name, provider_url):
    """Trace the block for a specific operation using its transaction hash"""
    # Find the transaction hash for this operation
    operation_tx_hash = None
    for tx_hash, test_name in tx_hashes.items():
        if test_name == operation_name:
            operation_tx_hash = tx_hash
            break
    
    if not operation_tx_hash:
        print_with_timestamp(f"❌ No {operation_name} operation transaction found")
        return
    
    # Get the block number from the transaction receipt
    try:
        receipt = soda_helper.web3.eth.get_transaction_receipt(operation_tx_hash)
        block_number = receipt.blockNumber
        print_with_timestamp(f"{operation_name.upper()} operation executed in block {block_number}")
        
        # Trace the entire block
        try:
            block_traces = debug_trace_block(block_number, provider_url)
            print_with_timestamp(f"📊 Block {block_number} contains {len(block_traces)} transaction traces")
            
            for i, trace in enumerate(block_traces):
                tx_hash = trace.get("txHash", f"tx_{i}")
                is_target = "🎯 TARGET" if str(tx_hash) == str(operation_tx_hash) else "📄"
                print_with_timestamp(f"\n{is_target} Transaction: {tx_hash}\n" + "-" * 60)
                    
        except Exception as e:
            print_with_timestamp(f"❌ Error tracing block {block_number}: {e}")
            
    except Exception as e:
        print_with_timestamp(f"❌ Error getting receipt for {operation_name} transaction: {e}")

def test_getUserKey(soda_helper, contract, a, public_key):
    signing_key = os.environ.get('SIGNING_KEY')
    signature = sign(public_key, bytes.fromhex(signing_key[2:]))
    tx_hash = execute_transaction_with_gas_estimation("get user key", soda_helper, contract, "userKeyTest", func_args=[public_key, signature])
    print_tx_data(tx_hash, "get_user_key", 'PrecompilesOffboardToUserKeyTestContract.sol', "userKeyTest")
    return execute_transaction_with_gas_estimation("offboard to user", soda_helper, contract, "offboardToUserTest", func_args=[a, soda_helper.get_account().address])

last_random_result = 0
last_random_bounded_result = 0

def test_random(soda_helper, contract):
    return execute_transaction("random", soda_helper, contract, "randomTest")

def test_randomBoundedBits(soda_helper, contract, numBits):
    return execute_transaction("random bounded", soda_helper, contract, "randomBoundedTest", func_args=[numBits])

def test_boolean(soda_helper, contract, bool_a, bool_b, bit):
    return execute_transaction_with_gas_estimation("boolean tests", soda_helper, contract, "booleanTest", func_args=[bool_a, bool_b, bit])

def get_tuple_type(param):
    # For tuple types, we need to get the internal structure
    if 'components' in param:
        tuple_types = []
        # Extract the actual tuple component types
        for comp in param['components']:
            if comp['type'] == 'tuple':
                tuple_types.append(get_tuple_type(comp))
            else:
                tuple_types.append(comp['type'])
        return f"({','.join(tuple_types)})"
    else:
        return 'tuple'

def get_function_signature(function_abi):
    """Get function signature from a provided function ABI"""
    # Extract the input types from the ABI
    input_types = []
    for param in function_abi.get('inputs', []):
        if param['type'] == 'tuple':
            input_types.append(get_tuple_type(param))
        else:
            input_types.append(param['type'])
    
    # Generate the function signature
    return f"{function_abi['name']}({','.join(input_types)})"

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
    function = contract.functions.validateCiphertextTest(dummyCT, dummyCT, dummyCT, dummyCT, dummyCT, dummySignature)
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(a, user_aes_key, Account.from_key(sign_key), contract, func_sig, bytes.fromhex(sign_key[2:]))
    return execute_transaction_with_gas_estimation("validate ciphertext", soda_helper, contract_str, "validateCiphertextTest", func_args=[ct, ct, ct, ct, ct, signature])

def test_validate_ciphertext_256(soda_helper, contract_str, a):
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
    function = contract.functions.validateCiphertext256Test(((dummyCT, dummyCT), dummySignature))
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    it = prepare_IT_256(a, user_aes_key, Account.from_key(sign_key), contract, func_sig, bytes.fromhex(sign_key[2:]))
    return execute_transaction_with_gas_estimation("validate ciphertext 256", soda_helper, contract_str, "validateCiphertext256Test", func_args=[it])


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
    function = contract.functions.validateCiphertextTest191(dummyCT, dummyCT, dummyCT, dummyCT, dummyCT, dummySignature)
    func_sig = get_function_signature(function.abi)  # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(a, user_aes_key, Account.from_key(sign_key), contract, func_sig,
                               bytes.fromhex(sign_key[2:]), eip191=True)
    return execute_transaction_with_gas_estimation("validate ciphertext eip191", soda_helper, contract_str,
                                                   "validateCiphertextTest191", func_args=[ct, ct, ct, ct, ct, signature])

def test_validate_ciphertext_256_eip191(soda_helper, contract_str, a):
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
    function = contract.functions.validateCiphertext256Test191(((dummyCT, dummyCT), dummySignature))
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    it = prepare_IT_256(a, user_aes_key, Account.from_key(sign_key), contract, func_sig, bytes.fromhex(sign_key[2:]))
    return execute_transaction_with_gas_estimation("validate ciphertext 256 eip191", soda_helper, contract_str, "validateCiphertext256Test191", func_args=[it])

def test_sha256(soda_helper, contract, a, b):
    return execute_transaction_with_gas_estimation("sha256Fixed432BitInput", soda_helper, contract, "sha256Fixed432BitInputTest", func_args=[a, b, b, soda_helper.account.address, 0, 0])


def checkResults(soda_helper, expected_results, private_key):
    
    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getAddResult")
    check_expected_result("addition", expected_results["addition"], result)

    result = soda_helper.call_contract_view('PrecompilesCheckedFuncsTestsContract.sol', "getAddResult")
    check_expected_result("checked_addition", expected_results["checked_addition"], result)

    overflow_bit, result = soda_helper.call_contract_view('PrecompilesCheckedWithOverflowFuncsTestsContract.sol', "getAddResult")
    check_expected_result("checked_addition_with_overflow_bit", expected_results["checked_addition_overflow_res"], result)
    check_expected_result("checked_addition_with_overflow_bit", expected_results["checked_addition_overflow_bit"], overflow_bit)

    overflow_bit = soda_helper.call_contract_view('PrecompilesCheckedWithOverflowFuncsTestsContract.sol', "getAddOverflow")
    check_expected_result("checked_addition_overflow", expected_results["checked_addition_overflow"], overflow_bit)

    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getSubResult")
    check_expected_result("subtract", expected_results["subtract"], result)

    result = soda_helper.call_contract_view('PrecompilesCheckedFuncsTestsContract.sol', "getSubResult")
    check_expected_result("checked_subtract", expected_results["checked_subtract"], result)

    overflow_bit, result = soda_helper.call_contract_view('PrecompilesCheckedWithOverflowFuncsTestsContract.sol', "getSubResult")
    check_expected_result("checked_subtract_with_overflow_bit", expected_results["checked_subtract_overflow_res"], result)
    check_expected_result("checked_subtract_with_overflow_bit", expected_results["checked_subtract_overflow_bit"], overflow_bit)

    overflow_bit = soda_helper.call_contract_view('PrecompilesCheckedWithOverflowFuncsTestsContract.sol', "getSubOverflow")
    check_expected_result("checked_subtract_overflow", expected_results["checked_subtract_overflow"], overflow_bit)

    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getMulResult")
    check_expected_result("multiplication", expected_results["multiplication"], result)

    result = soda_helper.call_contract_view('PrecompilesMul128_256TestsContract.sol', "getMulResult")
    check_expected_result("multiplication_128_256", expected_results["multiplication"], result)

    result = soda_helper.call_contract_view('PrecompilesCheckedFuncsTestsContract.sol', "getMulResult")
    check_expected_result("checked_multiplication", expected_results["multiplication"], result)

    result = soda_helper.call_contract_view('PrecompilesMul128_256TestsContract.sol', "getCheckedMulResult")
    check_expected_result("checked_multiplication_128_256", expected_results["multiplication"], result)

    overflow_bit, result = soda_helper.call_contract_view('PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', "getMulResult")
    check_expected_result("checked_multiplication_with_overflow_bit", expected_results["checked_multiplication_overflow_res"], result)
    check_expected_result("checked_multiplication_with_overflow_bit", expected_results["checked_multiplication_overflow_bit"], overflow_bit)

    overflow_bit, result = soda_helper.call_contract_view('PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', "getMulResult128_256")
    check_expected_result("checked_multiplication_with_overflow_128_256_bit", expected_results["checked_multiplication_overflow_res"], result)
    check_expected_result("checked_multiplication_with_overflow_128_256_bit", expected_results["checked_multiplication_overflow_bit"], overflow_bit)

    
    overflow_bit = soda_helper.call_contract_view('PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', "getMulOverflow")
    check_expected_result("checked_multiplication_overflow", expected_results["checked_multiplication_overflow"], overflow_bit)


    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getDivResult")
    check_expected_result("division", expected_results["division"], result)

    result = soda_helper.call_contract_view('PrecompilesDivRem128_256TestsContract.sol', "getDivResult")
    check_expected_result("division", expected_results["division"], result)
    
    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getRemResult")
    check_expected_result("reminder", expected_results["reminder"], result)

    result = soda_helper.call_contract_view('PrecompilesDivRem128_256TestsContract.sol', "getRemResult")
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
    
    result = soda_helper.call_contract_view('PrecompilesBitwise2TestsContract.sol', "getXorResult")
    check_expected_result("xor", expected_results["xor"], result)

    result8, result16, result32, result64, result128, result256 = soda_helper.call_contract_view('PrecompilesShiftTestsContract.sol', "getAllShiftResults")
    check_expected_result("bitwise shift left 8", expected_results["shift_left8"], result8)
    check_expected_result("bitwise shift left 16", expected_results["shift_left16"], result16)
    check_expected_result("bitwise shift left 32", expected_results["shift_left32"], result32)
    check_expected_result("bitwise shift left 64", expected_results["shift_left64"], result64)
    check_expected_result("bitwise shift left 128", expected_results["shift_left128"], result128)
    check_expected_result("bitwise shift left 256", expected_results["shift_left256"], result256)

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

    result = soda_helper.call_contract_view('PrecompilesComparison3TestsContract.sol', "getGeResult")
    check_expected_result("ge", expected_results["ge"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison1TestsContract.sol', "getGtResult")
    check_expected_result("gt", expected_results["gt"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison1TestsContract.sol', "getLeResult")
    check_expected_result("le", expected_results["le"], result)

    result = soda_helper.call_contract_view('PrecompilesComparison3TestsContract.sol', "getLtResult")
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

    new_a, new_b, res, allowance = soda_helper.call_contract_view('PrecompilesTransferAllowance128_256bitTestsContract.sol', "getResults")
    if not res:
        print_error_to_file(f'Test transfer with allowance failed.')
        raise Exception(f'Test transfer with allowance failed.')
    
    check_expected_result("transfer_allowance_128_256_bit", expected_results["transfer_a"], new_a)
    check_expected_result("transfer_allowance_128_256_bit", expected_results["transfer_b"], new_b)
    check_expected_result("transfer_allowance_128_256_bit", expected_results["transfer_allowance"], allowance)

    new_a, new_b, res, allowance = soda_helper.call_contract_view('PrecompilesTransferAllowanceScalarTestsContract.sol', "getResults")
    if not res:
        print_error_to_file(f'Test transfer with allowance scalar failed.')
        raise Exception(f'Test transfer with allowance scalar failed.')
    
    check_expected_result("transfer_allowance_scalar", expected_results["transfer_a"], new_a)
    check_expected_result("transfer_allowance_scalar", expected_results["transfer_b"], new_b)
    check_expected_result("transfer_allowance_scalar", expected_results["transfer_allowance"], allowance)

    new_a, new_b, res, allowance = soda_helper.call_contract_view('PrecompilesTransferAllowanceScalar256BitTestsContract.sol', "getResults")
    if not res:
        print_error_to_file(f'Test transfer with allowance scalar failed.')
        raise Exception(f'Test transfer with allowance scalar failed.')
    
    check_expected_result("transfer_allowance_scalar_256_bit", expected_results["transfer_a"], new_a)
    check_expected_result("transfer_allowance_scalar_256_bit", expected_results["transfer_b"], new_b)
    check_expected_result("transfer_allowance_scalar_256_bit", expected_results["transfer_allowance"], allowance)

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

    ct8, ct16, ct32, ct64, ct128, ct256High, ct256Low = soda_helper.call_contract_view("PrecompilesOffboardToUserKeyTestContract.sol", "getCTs")
    checkCt(ct8, decrypted_aes_key, expected_results["offboard_user"])
    checkCt(ct16, decrypted_aes_key, expected_results["offboard_user"])
    checkCt(ct32, decrypted_aes_key, expected_results["offboard_user"])
    checkCt(ct64, decrypted_aes_key, expected_results["offboard_user"])
    checkCt(ct128, decrypted_aes_key, expected_results["offboard_user"])
    checkCt256(ct256High, ct256Low, decrypted_aes_key, expected_results["offboard_user"])

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

    result = soda_helper.call_contract_view('PrecompilesMiscellaneous1TestsContract.sol', "getValidateCiphertextEip191Result")
    check_expected_result("validate_ciphertext_eip191", expected_results["validate_ciphertext"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneous1TestsContract.sol', "getValidateCiphertext256Result")
    check_expected_result("validate_ciphertext_256", expected_results["validate_ciphertext_256"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneous1TestsContract.sol', "getValidateCiphertext256Eip191Result")
    check_expected_result("validate_ciphertext_256_eip191", expected_results["validate_ciphertext_256"], result)

    result = soda_helper.call_contract_view('PrecompilesSHATestsContract.sol', "getSHAOutput")
    check_expected_result("SHA256Fixed43bitInput", expected_results["SHA256Fixed43bitInput"], result)

# Main test function
def run_tests(soda_helper, a, b, shift, bit, numBits, bool_a, bool_b, allowance, check_results, provider_url):
    expected_results = {}
    tx_hashes = {}

    # Test Addition
    print_with_timestamp("Run addition test...")
    tx_hash = test_addition(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b)
    print_tx_data(tx_hash, "addition", 'PrecompilesArythmeticTestsContract.sol', "addTest")
    tx_hashes[tx_hash] = "addition"
    expected_results["addition"] = a+b

    # Test Checked Addition
    print_with_timestamp("Run checked addition test...")
    tx_hash = test_checked_addition(soda_helper, 'PrecompilesCheckedFuncsTestsContract.sol', a, b)
    print_tx_data(tx_hash, "checked_addition", 'PrecompilesCheckedFuncsTestsContract.sol', "checkedAddTest")
    tx_hashes[tx_hash] = "checked_addition"
    expected_results["checked_addition"] = a+b

    # Test Checked Addition with Overflow Bit
    print_with_timestamp("Run checked addition with overflow bit test...")
    tx_hash = test_checked_addition_with_overflow_bit(soda_helper, 'PrecompilesCheckedWithOverflowFuncsTestsContract.sol', a, b)
    print_tx_data(tx_hash, "checked_addition_with_overflow_bit", 'PrecompilesCheckedWithOverflowFuncsTestsContract.sol', "checkedAddWithOverflowBitTest")
    tx_hashes[tx_hash] = "checked_addition_with_overflow_bit"
    expected_results["checked_addition_overflow_res"] = a+b
    expected_results["checked_addition_overflow_bit"] = True if a+b < a else False

    # Test Checked Addition that should overflow
    print_with_timestamp("Run overflow addition test ...")
    tx_hash = test_checked_addition_overflow(soda_helper, 'PrecompilesCheckedWithOverflowFuncsTestsContract.sol', MAX_UINT_8, a, MAX_UINT_16, b, MAX_UINT_32, a, MAX_UINT_64, b, MAX_UINT_128, a, MAX_UINT_256, b)
    print_tx_data(tx_hash, "checked_addition_overflow", 'PrecompilesCheckedWithOverflowFuncsTestsContract.sol', "checkedAddOverflowTest")
    tx_hashes[tx_hash] = "checked_addition_overflow"
    expected_results["checked_addition_overflow"] = True
    
    # Test Subtraction
    print_with_timestamp("Run subtraction test...")
    tx_hash = test_subtraction(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b)
    print_tx_data(tx_hash, "subtract", 'PrecompilesArythmeticTestsContract.sol', "subTest")
    tx_hashes[tx_hash] = "subtract"
    expected_results["subtract"] = a-b

    # Test Checked Subtraction
    print_with_timestamp("Run checked subtraction test...")
    tx_hash = test_checked_subtraction(soda_helper, 'PrecompilesCheckedFuncsTestsContract.sol', a, b)
    print_tx_data(tx_hash, "checked_subtract", 'PrecompilesCheckedFuncsTestsContract.sol', "checkedSubTest")
    tx_hashes[tx_hash] = "checked_subtract"
    expected_results["checked_subtract"] = a-b

    # Test Checked Subtraction with Overflow Bit
    print_with_timestamp("Run checked subtraction with overflow bit test...")
    tx_hash = test_checked_subtraction_with_overflow_bit(soda_helper, 'PrecompilesCheckedWithOverflowFuncsTestsContract.sol', a, b)
    print_tx_data(tx_hash, "checked_subtract_with_overflow_bit", 'PrecompilesCheckedWithOverflowFuncsTestsContract.sol', "checkedSubWithOverflowBitTest")
    tx_hashes[tx_hash] = "checked_subtract_with_overflow_bit"
    expected_results["checked_subtract_overflow_res"] = a-b
    expected_results["checked_subtract_overflow_bit"] = True if a-b > a else False

    # Test Checked Subtraction that should overflow
    print_with_timestamp("Run overflow subtraction test ...")
    tx_hash = test_checked_subtraction_overflow(soda_helper, 'PrecompilesCheckedWithOverflowFuncsTestsContract.sol', a, MAX_UINT_8)
    print_tx_data(tx_hash, "checked_subtraction_overflow", 'PrecompilesCheckedWithOverflowFuncsTestsContract.sol', "checkedSubOverflowTest")
    tx_hashes[tx_hash] = "checked_subtraction_overflow"
    expected_results["checked_subtract_overflow"] = True

    # Test Multiplication
    print_with_timestamp("Run multiplication test...")
    tx_hash = test_multiplication(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b)
    print_tx_data(tx_hash, "multiplication", 'PrecompilesArythmeticTestsContract.sol', "mulTest")
    tx_hashes[tx_hash] = "multiplication"
    expected_results["multiplication"] = a*b

    # Test Multiplication 128-256 bits
    print_with_timestamp("Run multiplication 128-256 test...")
    tx_hash = test_multiplication(soda_helper, 'PrecompilesMul128_256TestsContract.sol', a, b)
    print_tx_data(tx_hash, "multiplication", 'PrecompilesMul128_256TestsContract.sol', "mulTest")
    tx_hashes[tx_hash] = "multiplication_128_256"

    # Test checked Multiplication
    print_with_timestamp("Run checked multiplication test...")
    tx_hash = test_checked_multiplication(soda_helper, 'PrecompilesCheckedFuncsTestsContract.sol', a, b)
    print_tx_data(tx_hash, "checked_multiplication", 'PrecompilesCheckedFuncsTestsContract', "checkedMulTest")
    tx_hashes[tx_hash] = "checked_multiplication"

    # Test checked Multiplication 128-256 bits
    print_with_timestamp("Run checked multiplication test...")
    tx_hash = test_checked_multiplication(soda_helper, 'PrecompilesMul128_256TestsContract.sol', a, b)
    print_tx_data(tx_hash, "checked_multiplication", 'PrecompilesMul128_256TestsContract', "checkedMulTest")
    tx_hashes[tx_hash] = "checked_multiplication_128_256"

    # Test Multiplication with overflow bit
    print_with_timestamp("Run checked multiplication with overflow bit test...")
    tx_hash = test_checked_multiplication_with_overflow_bit(soda_helper, 'PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', a, b)
    print_tx_data(tx_hash, "checked_multiplication_overflow_res", 'PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', "checkedMulWithOverflowBitTest")
    tx_hashes[tx_hash] = "checked_multiplication_overflow_res"
    expected_results["checked_multiplication_overflow_res"] = a*b
    expected_results["checked_multiplication_overflow_bit"] = True if a*b < a else False

    # Test Multiplication with overflow bit 128-256 bits
    print_with_timestamp("Run checked multiplication with overflow bit for 128-256 bits test...")
    tx_hash = test_checked_multiplication_with_overflow_bit_128_256(soda_helper, 'PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', a, b)
    print_tx_data(tx_hash, "checked_multiplication_overflow_128_256_res", 'PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', "checkedMulWithOverflowBit128_256Test")
    tx_hashes[tx_hash] = "checked_multiplication_overflow_bit_128_256"

    # Test Checked Multiplication that should overflow
    print_with_timestamp("Run overflow multiplication test ...")
    tx_hash = test_checked_multiplication_overflow(soda_helper, 'PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', MAX_UINT_8, a, MAX_UINT_16, b, MAX_UINT_32, a, MAX_UINT_64, b, MAX_UINT_128, a, MAX_UINT_256, b)
    print_tx_data(tx_hash, "checked_multiplication_overflow", 'PrecompilesCheckedWithOverflowFuncs1TestsContract.sol', "checkedMulOverflowTest")
    tx_hashes[tx_hash] = "checked_multiplication_overflow"
    expected_results["checked_multiplication_overflow"] = True

    # Test Division
    print_with_timestamp("Run division test...")
    tx_hash = test_division(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, b)
    print_tx_data(tx_hash, "division", 'PrecompilesMiscellaneousTestsContract.sol', "divTest")
    tx_hashes[tx_hash] = "division"
    expected_results["division"] = a/b

    # Test Division 128-256
    print_with_timestamp("Run division 128-256 test...")
    tx_hash = test_division(soda_helper, 'PrecompilesDivRem128_256TestsContract.sol', a, b)
    print_tx_data(tx_hash, "division_128_256", 'PrecompilesDivRem128_256TestsContract.sol', "divTest")
    tx_hashes[tx_hash] = "division_128_256"

    # Test Remainder
    print_with_timestamp("Run remainder test...")
    tx_hash = test_remainder(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, b)
    print_tx_data(tx_hash, "reminder", 'PrecompilesMiscellaneousTestsContract.sol', "remTest")
    tx_hashes[tx_hash] = "reminder"
    expected_results["reminder"] = a%b

    # Test Remainder 128-256
    print_with_timestamp("Run remainder 128-256 test...")
    tx_hash = test_remainder(soda_helper, 'PrecompilesDivRem128_256TestsContract.sol', a, b)
    print_tx_data(tx_hash, "reminder_128_256", 'PrecompilesDivRem128_256TestsContract.sol', "remTest")
    tx_hashes[tx_hash] = "reminder_128_256"

    # Test Mux
    print_with_timestamp("Run mux test...")
    tx_hash = test_mux(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', bit, a, b)
    print_tx_data(tx_hash, "mux", 'PrecompilesMiscellaneousTestsContract.sol', "muxTest")
    tx_hashes[tx_hash] = "mux"
    expected_results["mux"] = a if bit == 0 else b

    # Test Offboard_Onboard
    print_with_timestamp("Run offboard_Onboard test...")
    tx_hash = test_offboardOnboard(soda_helper, 'PrecompilesOffboardToUserKeyTestContract.sol', a)
    print_tx_data(tx_hash, "onboard_offboard", 'PrecompilesOffboardToUserKeyTestContract.sol', "offboardOnboardTest")
    tx_hashes[tx_hash] = "onboard_offboard"
    expected_results["onboard_offboard"] = a

    # test Not
    print_with_timestamp("Run not test...")
    tx_hash = test_not(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', bit)
    print_tx_data(tx_hash, "not", 'PrecompilesMiscellaneousTestsContract.sol', "notTest")
    tx_hashes[tx_hash] = "not"
    expected_results["not"] = not bit

    # Test Bitwise AND
    print_with_timestamp("Run and test...")
    tx_hash = test_bitwise_and(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b)
    print_tx_data(tx_hash, "and", 'PrecompilesBitwiseTestsContract.sol', "andTest")
    tx_hashes[tx_hash] = "and"
    expected_results["and"] = a & b

    # Test Bitwise OR
    print_with_timestamp("Run or test...")
    tx_hash = test_bitwise_or(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b)
    print_tx_data(tx_hash, "or", 'PrecompilesBitwiseTestsContract.sol', "orTest")
    tx_hashes[tx_hash] = "or"
    expected_results["or"] = a | b

    # Test Bitwise XOR
    print_with_timestamp("Run xor test...")
    tx_hash = test_bitwise_xor(soda_helper, 'PrecompilesBitwise2TestsContract.sol', a, b)
    print_tx_data(tx_hash, "xor", 'PrecompilesBitwise2TestsContract.sol', "xorTest")
    tx_hashes[tx_hash] = "xor"
    expected_results["xor"] = a ^ b

    # Test Bitwise Shift Left
    print_with_timestamp("Run shift left test...")
    tx_hash = test_bitwise_shift_left(soda_helper, 'PrecompilesShiftTestsContract.sol', a, shift) 
    print_tx_data(tx_hash, "shl", 'PrecompilesShiftTestsContract.sol', "shlTest")
    tx_hashes[tx_hash] = "shl"
    # Calculate the result in 8, 16, 32, and 64 bit
    expected_results["shift_left8"] = (a << shift) & 0xFF
    expected_results["shift_left16"] = (a << shift) & 0xFFFF
    expected_results["shift_left32"] = (a << shift) & 0xFFFFFFFF
    expected_results["shift_left64"] = (a << shift) & 0xFFFFFFFFFFFFFFFF
    expected_results["shift_left128"] = (a << shift) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    expected_results["shift_left256"] = (a << shift) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    # Test Bitwise Shift Right
    print_with_timestamp("Run shift right test...")
    tx_hash = test_bitwise_shift_right(soda_helper, 'PrecompilesShiftTestsContract.sol', a, shift)
    print_tx_data(tx_hash, "shr", 'PrecompilesShiftTestsContract.sol', "shrTest")
    tx_hashes[tx_hash] = "shr"
    expected_results["shift_right"] = a >> shift

    # Test Min
    print_with_timestamp("Run min test...")
    tx_hash = test_min(soda_helper, 'PrecompilesMinMaxTestsContract.sol', a, b)
    print_tx_data(tx_hash, "min", 'PrecompilesMinMaxTestsContract.sol', "minTest")
    tx_hashes[tx_hash] = "min"
    expected_results["min"] = min(a, b)

    # Test Max
    print_with_timestamp("Run max test...")
    tx_hash = test_max(soda_helper, 'PrecompilesMinMaxTestsContract.sol', a, b)
    print_tx_data(tx_hash, "max", 'PrecompilesMinMaxTestsContract.sol', "maxTest")
    tx_hashes[tx_hash] = "max"
    expected_results["max"] = max(a, b)

    # Test Equality
    print_with_timestamp("Run equality test...")
    tx_hash = test_eq(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b)
    print_tx_data(tx_hash, "eq", 'PrecompilesComparison2TestsContract.sol', "eqTest")
    tx_hashes[tx_hash] = "eq"
    expected_results["eq"] = (a == b)

    # Test Not Equal
    print_with_timestamp("Run not equal test...")
    tx_hash = test_ne(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b)
    print_tx_data(tx_hash, "ne", 'PrecompilesComparison2TestsContract.sol', "neTest")
    tx_hashes[tx_hash] = "ne"
    expected_results["ne"] = (a != b)

    # Test Greater Than or Equal
    print_with_timestamp("Run greater than or equal test...")
    tx_hash = test_ge(soda_helper, 'PrecompilesComparison3TestsContract.sol', a, b)
    print_tx_data(tx_hash, "ge", 'PrecompilesComparison3TestsContract.sol', "geTest")
    tx_hashes[tx_hash] = "ge"
    expected_results["ge"] = (a >= b)

    # Test Greater Than
    print_with_timestamp("Run greater than test...")
    tx_hash = test_gt(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b)
    print_tx_data(tx_hash, "gt", 'PrecompilesComparison1TestsContract.sol', "gtTest")
    tx_hashes[tx_hash] = "gt"
    expected_results["gt"] = (a > b)

    # Test Less Than or Equal
    print_with_timestamp("Run less than or equal test...")
    tx_hash = test_le(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b)
    print_tx_data(tx_hash, "le", 'PrecompilesComparison1TestsContract.sol', "leTest")
    tx_hashes[tx_hash] = "le"
    expected_results["le"] = (a <= b)

    # Test Less Than
    print_with_timestamp("Run less than test...")
    tx_hash = test_lt(soda_helper, 'PrecompilesComparison3TestsContract.sol', a, b)
    print_tx_data(tx_hash, "lt", 'PrecompilesComparison3TestsContract.sol', "ltTest")
    tx_hashes[tx_hash] = "lt"
    expected_results["lt"] = (a < b)

    # Test Transfer
    print_with_timestamp("Run transfer test...")
    tx_hash = test_transfer(soda_helper, 'PrecompilesTransferTestsContract.sol', a, b, b)
    print_tx_data(tx_hash, "transfer", 'PrecompilesTransferTestsContract.sol', "transferTest")
    tx_hashes[tx_hash] = "transfer"
    expected_results["transfer_a"] = a - b
    expected_results["transfer_b"] = b + b
    
    # Test Transfer scalar
    print_with_timestamp("Run transfer scalar test...")
    tx_hash = test_transfer(soda_helper, 'PrecompilesTransferScalarTestsContract.sol', a, b, b)
    print_tx_data(tx_hash, "transfer_scalar", 'PrecompilesTransferScalarTestsContract.sol', "transferTest")
    tx_hashes[tx_hash] = "transfer_scalar"

    # Test Transfer with allowance
    print_with_timestamp("Run transfer with allowance test...")
    tx_hash = test_transfer_allowance(soda_helper, 'PrecompilesTransferAllowanceTestsContract.sol', a, b, b, allowance)
    print_tx_data(tx_hash, "transfer_allowance", 'PrecompilesTransferAllowanceTestsContract.sol', "transferWithAllowanceTest")
    tx_hashes[tx_hash] = "transfer_allowance"
    expected_results["transfer_allowance"] = allowance - b

    # Test Transfer with allowance 128 and 256 bit
    print_with_timestamp("Run transfer with allowance 128 and 256 bit test...")
    tx_hash = test_transfer_allowance(soda_helper, 'PrecompilesTransferAllowance128_256bitTestsContract.sol', a, b, b, allowance)
    print_tx_data(tx_hash, "transfer_allowance_128_256_bit", 'PrecompilesTransferAllowance128_256bitTestsContract.sol', "transferWithAllowanceTest")
    tx_hashes[tx_hash] = "transfer_allowance_128_256_bit"

    # Test Transfer with allowance scalar
    print_with_timestamp("Run transfer with allowance scalar test...")
    tx_hash = test_transfer_allowance(soda_helper, 'PrecompilesTransferAllowanceScalarTestsContract.sol', a, b, b, allowance)
    print_tx_data(tx_hash, "transfer_allowance_scalar", 'PrecompilesTransferAllowanceScalarTestsContract.sol', "transferWithAllowanceTest")
    tx_hashes[tx_hash] = "transfer_allowance_scalar"

    # Test Transfer with allowance scalar 256 bit
    print_with_timestamp("Run transfer with allowance scalar 256 bit test...")
    tx_hash = test_transfer_allowance(soda_helper, 'PrecompilesTransferAllowanceScalar256BitTestsContract.sol', a, b, b, allowance)
    print_tx_data(tx_hash, "transfer_allowance_256_bit", 'PrecompilesTransferAllowanceScalar256BitTestsContract.sol', "transferWithAllowanceTest")
    tx_hashes[tx_hash] = "transfer_allowance_256_bit"

    # Test boolean functions
    print_with_timestamp("Run Boolean functions test...")
    tx_hash = test_boolean(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', bool_a, bool_b, bit)
    print_tx_data(tx_hash, "boolean", 'PrecompilesMiscellaneous1TestsContract.sol', "booleanTest")
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
    print_tx_data(tx_hash, "offboard_user", 'PrecompilesOffboardToUserKeyTestContract.sol', "offboardToUserTest")
    tx_hashes[tx_hash] = "offboard_user"
    expected_results["offboard_user"] = a

    # Test Validate Ciphertext
    print_with_timestamp("Run validate ciphertext test...")
    tx_hash = test_validate_ciphertext(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', a)
    print_tx_data(tx_hash, "validate_ciphertext", 'PrecompilesMiscellaneous1TestsContract.sol', "validateCiphertextTest")
    tx_hashes[tx_hash] = "validate_ciphertext"
    expected_results["validate_ciphertext"] = a

    # Test Validate Ciphertext 256 bit
    print_with_timestamp("Run validate ciphertext test...")
    tx_hash = test_validate_ciphertext_256(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol',(a << 128 | a))
    print_tx_data(tx_hash, "validate_ciphertext_256", 'PrecompilesMiscellaneous1TestsContract.sol', "validateCiphertext256Test")
    tx_hashes[tx_hash] = "validate_ciphertext_256"
    expected_results["validate_ciphertext_256"] = ((a << 128) | a)

    # Test Validate Ciphertext with eip191
    print_with_timestamp("Run validate ciphertext eip191 test...")
    tx_hash = test_validate_ciphertext_eip191(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', a)
    print_tx_data(tx_hash, "validate_ciphertext_eip191", 'PrecompilesMiscellaneous1TestsContract.sol', "validateCiphertextTest191")
    tx_hashes[tx_hash] = "validate_ciphertext_eip191"

    # Test Validate Ciphertext 256 bit eip191
    print_with_timestamp("Run validate ciphertext 256 bit eip191 test...")
    tx_hash = test_validate_ciphertext_256_eip191(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', (a << 128 | a))
    print_tx_data(tx_hash, "validate_ciphertext_256_eip191", 'PrecompilesMiscellaneous1TestsContract.sol', "validateCiphertext256Test191")
    tx_hashes[tx_hash] = "validate_ciphertext_256_eip191"

    # test random
    print_with_timestamp("Run random test...")
    tx_hash = test_random(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol')
    print_tx_data(tx_hash, "random", 'PrecompilesMiscellaneous1TestsContract.sol', "randomTest")
    tx_hashes[tx_hash] = "random"

    # test random bounded bits
    print_with_timestamp("Run random Bounded Bits test...")
    tx_hash = test_randomBoundedBits(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', numBits)
    print_tx_data(tx_hash, "random_bounded", 'PrecompilesMiscellaneous1TestsContract.sol', "randomBoundedTest")
    tx_hashes[tx_hash] = "random_bounded"

    # test SHA256Fixed43bitInput
    print_with_timestamp("Run SHA256 with fixed 432 bit input test...")
    tx_hash = test_sha256(soda_helper, 'PrecompilesSHATestsContract.sol', a, b)
    print_tx_data(tx_hash, "SHA256Fixed43bitInput", 'PrecompilesSHATestsContract.sol', "sha256Fixed432BitInputTest")
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
    
    current_sleep_time = 0
    tx_receipts = set()
    print_with_timestamp(f"Wait for transaction receipts...")
    while len(tx_receipts) < len(tx_hashes) and current_sleep_time < MAX_SLEEP_TIME:
        for h, name in tx_hashes.items():
            if h in tx_receipts:
                continue
            try:
                r = soda_helper.web3.eth.get_transaction_receipt(h.hex())
                if r is not None:
                    if r.status == 0:
                        print(r)
                        print_error_to_file(f'Transaction {name} reverted.')
                        raise Exception(f'Transaction {name} reverted.')
                tx_receipts.add(h)
                print(f"Got {len(tx_receipts)} out of {len(tx_hashes)} receipts")
            except TransactionNotFound as e:
                pass
        current_sleep_time += 1
        sleep(1)

    if len(tx_receipts) < len(tx_hashes):
        print_error_to_file(f'Not all transactions were mined after {MAX_SLEEP_TIME} seconds.')
        raise Exception(f'Not all transactions were mined after {MAX_SLEEP_TIME} seconds.')

    checkResults(soda_helper, expected_results, private_key)
    
    # Now verify trace results for specified operations after all receipts are available
    print_with_timestamp("Verifying trace results for specified operations...")
    
    # Verify addition trace
    verify_trace_for_operation(soda_helper, tx_hashes, "addition", {"a": a, "b": b}, (a + b), lambda a, b: (a + b), provider_url)
    
    # Verify subtraction trace
    verify_trace_for_operation(soda_helper, tx_hashes, "subtract", {"a": a, "b": b}, (a - b), lambda a, b: (a - b), provider_url)
    
    # Trace blocks for specific operations
    print_with_timestamp("Tracing blocks for specific operations...")
    
    # Trace blocks for operations
    trace_block_for_operation(soda_helper, tx_hashes, "and", provider_url)

def runTestVectors(soda_helper, check_results, provider_url):

    print_with_timestamp(f'\nTest Vector 0\n')

    #  test vector 0
    run_tests(soda_helper, 10, 5, 2, False, 7, True, False, 7, check_results, provider_url)

    print_with_timestamp(f'\nTest Vector 1\n')

    #  test vector 1
    run_tests(soda_helper, 100, 2, 10, True, 8, False, False, 80, check_results, provider_url)


def main(provider_url: str, check_results: bool):

    print_with_timestamp("Running tests...")
    soda_helper = setup(provider_url)

    # Run the tests
    runTestVectors(soda_helper, check_results, provider_url)

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

    # Ensure logs directory exists
    os.makedirs('logs', exist_ok=True)

    global OUTPUT_FILE
    OUTPUT_FILE = f'logs/{args.output_file}'
    
    global transaction_log_file
    match = re.search(r"(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})", args.output_file)
    if match:
        timestamp = match.group(1)
        transaction_log_file = f'logs/{timestamp}-transactions_log.txt'

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
