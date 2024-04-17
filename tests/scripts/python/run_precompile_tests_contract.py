import os
import sys
sys.path.append('soda-sdk')
from python.crypto import generate_aes_key, write_aes_key, generate_rsa_keypair, decrypt_rsa, encrypt_rsa, sign, decrypt
from lib.python.soda_web3_helper import SodaWeb3Helper, REMOTE_HTTP_PROVIDER_URL, LOCAL_PROVIDER_URL
import argparse

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

def setup(provider_url: str):
    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)

    # Compile the contracts
    for file_name in SOLIDITY_FILES:
        success = soda_helper.setup_contract("tests/contracts/" + file_name, file_name)
        if not success:
            print("Failed to set up the contract")

        # Deploy the contract
        receipt = soda_helper.deploy_contract(file_name, constructor_args=[])
        if receipt is None:
            print("Failed to deploy the contract")

    return soda_helper

def execute_and_check_result(name, expected_result, soda_helper, contract, func_name, func_args=[]):
    receipt = soda_helper.call_contract_transaction(contract, func_name, func_args=func_args)
    if receipt is None:
        print("Failed to call the transaction function")
    result = soda_helper.call_contract_view(contract, "getResult")
    check_expected_result(name, expected_result, result)

def check_expected_result(name, expected_result, result):
    if result == expected_result:
        print(f'Test {name} succeeded: {result}')
    else:
        raise ValueError(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')


# Test functions
def test_addition(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("addition", expected_result, soda_helper, contract, "addTest", func_args=[a, b])

def test_subtraction(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("subtraction", expected_result, soda_helper, contract, "subTest", func_args=[a, b])

def test_multiplication(soda_helper, contract, a, b, expected_result):
    soda_helper.call_contract_transaction(contract, "mulTest", func_args=[a, b])
    result = soda_helper.call_contract_view(contract, "getResult16")
    check_expected_result("multiplication", expected_result, result)

def test_division(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("division", expected_result, soda_helper, contract, "divTest", func_args=[a, b])

def test_remainder(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("reminder", expected_result, soda_helper, contract, "remTest", func_args=[a, b])

def test_bitwise_and(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("bitwise and", expected_result, soda_helper, contract, "andTest", func_args=[a, b])

def test_bitwise_or(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("bitwise or", expected_result, soda_helper, contract, "orTest", func_args=[a, b])

def test_bitwise_xor(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("bitwise xor", expected_result, soda_helper, contract, "xorTest", func_args=[a, b])

def test_bitwise_shift_left(soda_helper, contract, a, b, expected_result8, expected_result16, expected_result32, expected_result64):
    soda_helper.call_contract_transaction(contract, "shlTest", func_args=[a, b])
    result8, result16, result32, result64 = soda_helper.call_contract_view(contract, "getAllShiftResults")
    check_expected_result("bitwise shift left 8", expected_result8, result8)
    check_expected_result("bitwise shift left 16", expected_result16, result16)
    check_expected_result("bitwise shift left 32", expected_result32, result32)
    check_expected_result("bitwise shift left 64", expected_result64, result64)

def test_bitwise_shift_right(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("bitwise shift right", expected_result, soda_helper, contract, "shrTest", func_args=[a, b])

def test_min(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("min", expected_result, soda_helper, contract, "minTest", func_args=[a, b])

def test_max(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("max", expected_result, soda_helper, contract, "maxTest", func_args=[a, b])

def test_eq(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("equality", expected_result, soda_helper, contract, "eqTest", func_args=[a, b])

def test_ne(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("not equal", expected_result, soda_helper, contract, "neTest", func_args=[a, b])

def test_ge(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("greater than or equal", expected_result, soda_helper, contract, "geTest", func_args=[a, b])

def test_gt(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("greater than", expected_result, soda_helper, contract, "gtTest", func_args=[a, b])

def test_le(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("less than or equal", expected_result, soda_helper, contract, "leTest", func_args=[a, b])

def test_lt(soda_helper, contract, a, b, expected_result):
    execute_and_check_result("less than", expected_result, soda_helper, contract, "ltTest", func_args=[a, b])

def test_mux(soda_helper, contract, selectionBit, a, b, expected_result):
    execute_and_check_result("mux", expected_result, soda_helper, contract, "muxTest", func_args=[selectionBit, a, b])

def test_transfer(soda_helper, contract, a, b, amount, expected_result_a, expected_result_b):
    receipt = soda_helper.call_contract_transaction(contract, "transferTest", func_args=[a, b, amount])
    if receipt is None:
        print("Failed to call the transaction function")
    new_a, new_b, res = soda_helper.call_contract_view(contract, "getResults")
    if not res:
        print(f'Test transfer Failed.')
    
    check_expected_result("transfer", expected_result_a, new_a)
    check_expected_result("transfer", expected_result_b, new_b)

def test_offboardOnboard(soda_helper, contract, a, expected_result):
    execute_and_check_result("offboard_Onboard", expected_result, soda_helper, contract, "offboardOnboardTest", func_args=[a, a, a, a])

def test_not(soda_helper, contract, bit, expected_result):
    soda_helper.call_contract_transaction(contract, "notTest", func_args=[bit])
    result = soda_helper.call_contract_view(contract, "getBoolResult")
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

def test_getUserKey(soda_helper, contract, a, expected_result):
    private_key, public_key = generate_rsa_keypair()
    signedEK = sign(public_key, bytes.fromhex("2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"))
    encryptedUserKey = soda_helper.call_contract_view(contract, "userKeyTest", func_args=[public_key, signedEK])
    decrypted_aes_key = decrypt_rsa(private_key, encryptedUserKey)

    soda_helper.call_contract_transaction(contract, "offboardToUserTest", func_args=[a, soda_helper.get_account().address])
    ct8, ct16, ct32, ct64 = soda_helper.call_contract_view(contract, "getCTs")
    checkCt(ct8, decrypted_aes_key, expected_result)
    checkCt(ct16, decrypted_aes_key, expected_result)
    checkCt(ct32, decrypted_aes_key, expected_result)
    checkCt(ct64, decrypted_aes_key, expected_result)

last_random_result = 0

def test_random(soda_helper, contract):
    global last_random_result  # Use the global keyword to use and modify the global variable
    soda_helper.call_contract_transaction(contract, "randomTest")
    result = soda_helper.call_contract_view(contract, "getRandom")
    if result != last_random_result:
        print(f'Test Random succeeded: {result}')
        last_random_result = result
    else:
        raise ValueError(f'Test Random failed.')

def test_randomBoundedBits(soda_helper, contract, numBits):
    global last_random_result  # Use the global keyword to use and modify the global variable
    soda_helper.call_contract_transaction(contract, "randomBoundedTest", func_args=[numBits])
    result = soda_helper.call_contract_view(contract, "getRandom")
    if result != last_random_result:
        print(f'Test RandomBoundedBits succeeded: {result}')
        last_random_result = result
    else:
        raise ValueError(f'Test RandomBoundedBits failed.')

def test_boolean(soda_helper, contract, bool_a, bool_b, bit):
    receipt = soda_helper.call_contract_transaction(contract, "booleanTest", func_args=[bool_a, bool_b, bit])
    if receipt is None:
        print("Failed to call the transaction function")
    andRes, orRes, xorRes, notRes, eqRes, neqRes, muxRes, onboardRes = soda_helper.call_contract_view(contract, "getBooleanResults")
    check_expected_result("boolean_and", bool_a and bool_b, andRes)
    check_expected_result("boolean_or", bool_a or bool_b, orRes)
    check_expected_result("boolean_xor", bool_a ^ bool_b, xorRes)
    check_expected_result("boolean_not", not bool_a, notRes)
    check_expected_result("boolean_equal", bool_a == bool_b, eqRes)
    check_expected_result("boolean_notEqual", bool_a != bool_b, neqRes)
    check_expected_result("boolean_mux", bool_b if bit else bool_a, muxRes)
    check_expected_result("boolean_onboard_offboard", bool_a, onboardRes)


# Main test function
def run_tests(soda_helper, a, b, shift, bit, numBits, bool_a, bool_b):
    # Test Addition
    test_addition(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b, a + b)
    
    # Test Subtraction
    test_subtraction(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b, a - b)

    # Test Multiplication
    test_multiplication(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b, a * b)

    # Test Division
    test_division(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, b, a / b)

    # Test Remainder
    test_remainder(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, b, a % b)

    # # Test Bitwise AND
    test_bitwise_and(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b, a & b)

    # # Test Bitwise OR
    test_bitwise_or(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b, a | b)

    # # Test Bitwise XOR
    test_bitwise_xor(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b, a ^ b)

    # Test Bitwise Shift Left
    test_bitwise_shift_left(soda_helper, 'PrecompilesShiftTestsContract.sol', a, shift, (a << shift) & 0xFF, (a << shift) & 0xFFFF, (a << shift) & 0xFFFFFFFF, (a << shift) & 0xFFFFFFFFFFFFFFFF) # Calculate the result in 8, 16, 32, and 64 bit

    # Test Bitwise Shift Right
    test_bitwise_shift_right(soda_helper, 'PrecompilesShiftTestsContract.sol', a, shift, a >> shift)

    # Test Min
    test_min(soda_helper, 'PrecompilesMinMaxTestsContract.sol', a, b, min(a, b))

    # Test Max
    test_max(soda_helper, 'PrecompilesMinMaxTestsContract.sol', a, b, max(a, b))

    # Test Equality
    test_eq(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b, a == b)

    # Test Not Equal
    test_ne(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b, a != b)

    # Test Greater Than or Equal
    test_ge(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b, a >= b)

    # Test Greater Than
    test_gt(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b, a > b)

    # Test Less Than or Equal
    test_le(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b, a <= b)

    # Test Less Than
    test_lt(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b, a < b)

    # Test Mux
    test_mux(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', bit, a, b, a if bit == 0 else b)

    # Test Transfer
    test_transfer(soda_helper, 'PrecompilesTransferTestsContract.sol', a, b, b, a - b, b + b)
    
    # Test Transfer scalar
    test_transfer(soda_helper, 'PrecompilesTransferScalarTestsContract.sol', a, b, b, a - b, b + b)

    # Test Offboard_Onboard
    test_offboardOnboard(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, a)

    # test not
    test_not(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', bit, not bit)

    # test getUserKey
    test_getUserKey(soda_helper, 'PrecompilesOffboardToUserKeyTestContract.sol', a, a)

    # test random
    test_random(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol')

    # test random bounded bits
    test_randomBoundedBits(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', numBits)

    test_boolean(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', bool_a, bool_b, bit)


def runTestVectors(soda_helper):

    print(f'\nTest Vector 0\n')

    #  test vector 0
    run_tests(soda_helper, 10, 5, 2, False, 7, True, False)

    print(f'\nTest Vector 1\n')

    #  test vector 1
    run_tests(soda_helper, 100, 50, 10, True, 8, False, False)

def main(provider_url: str):
    print("Running tests...")
    soda_helper = setup(provider_url)
    
    # Run the tests
    runTestVectors(soda_helper)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get URL.')
    parser.add_argument('provider_url', type=str, help='The node url')
    args = parser.parse_args()
    if args.provider_url == "Local":
        main(LOCAL_PROVIDER_URL)
    elif args.provider_url == "Remote":
        main(REMOTE_HTTP_PROVIDER_URL)
    else:
        print("Invalid provider url")
