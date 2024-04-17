import os
import sys
from time import sleep
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
    # sleep(10)
    # result = soda_helper.call_contract_view(contract, "getResult")
    # check_expected_result(name, expected_result, result)

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
    # sleep(10)
    # result = soda_helper.call_contract_view(contract, "getResult16")
    # check_expected_result("multiplication", expected_result, result)

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
    # sleep(10)
    # result8, result16, result32, result64 = soda_helper.call_contract_view(contract, "getAllShiftResults")
    # check_expected_result("bitwise shift left 8", expected_result8, result8)
    # check_expected_result("bitwise shift left 16", expected_result16, result16)
    # check_expected_result("bitwise shift left 32", expected_result32, result32)
    # check_expected_result("bitwise shift left 64", expected_result64, result64)

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
    # sleep(10)
    # new_a, new_b, res = soda_helper.call_contract_view(contract, "getResults")
    # if not res:
    #     print(f'Test transfer Failed.')
    
    # check_expected_result("transfer", expected_result_a, new_a)
    # check_expected_result("transfer", expected_result_b, new_b)

def test_offboardOnboard(soda_helper, contract, a, expected_result):
    execute_and_check_result("offboard_Onboard", expected_result, soda_helper, contract, "offboardOnboardTest", func_args=[a, a, a, a])

def test_not(soda_helper, contract, bit, expected_result):
    soda_helper.call_contract_transaction(contract, "notTest", func_args=[bit])
    # result = soda_helper.call_contract_view(contract, "getBoolResult")
    # check_expected_result("not", expected_result, result)
 
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

def test_getUserKey(soda_helper, contract, a, expected_result, public_key):
    signedEK = sign(public_key, bytes.fromhex("2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"))
    soda_helper.call_contract_transaction(contract, "userKeyTest", func_args=[public_key, signedEK])
    # encryptedUserKey = soda_helper.call_contract_view(contract, "getUserKey")
    # decrypted_aes_key = decrypt_rsa(private_key, encryptedUserKey)

    # soda_helper.call_contract_transaction(contract, "offboardToUserTest", func_args=[a, soda_helper.get_account().address])
    # ct8, ct16, ct32, ct64 = soda_helper.call_contract_view(contract, "getCTs")
    # checkCt(ct8, decrypted_aes_key, expected_result)
    # checkCt(ct16, decrypted_aes_key, expected_result)
    # checkCt(ct32, decrypted_aes_key, expected_result)
    # checkCt(ct64, decrypted_aes_key, expected_result)

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
    # andRes, orRes, xorRes, notRes, eqRes, neqRes, muxRes, onboardRes = soda_helper.call_contract_view(contract, "getBooleanResults")
    # check_expected_result("boolean_and", bool_a and bool_b, andRes)
    # check_expected_result("boolean_or", bool_a or bool_b, orRes)
    # check_expected_result("boolean_xor", bool_a ^ bool_b, xorRes)
    # check_expected_result("boolean_not", not bool_a, notRes)
    # check_expected_result("boolean_equal", bool_a == bool_b, eqRes)
    # check_expected_result("boolean_notEqual", bool_a != bool_b, neqRes)
    # check_expected_result("boolean_mux", bool_b if bit else bool_a, muxRes)
    # check_expected_result("boolean_onboard_offboard", bool_a, onboardRes)

def checkResults(soda_helper, expected_results):
    sleep(20)
    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getAddResult")
    check_expected_result("addition", expected_results["addition"], result)

    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getSubResult")
    check_expected_result("subtract", expected_results["subtract"], result)

    result = soda_helper.call_contract_view('PrecompilesArythmeticTestsContract.sol', "getResult16")
    check_expected_result("multiplication", expected_results["multiplication"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getDivResult")
    check_expected_result("division", expected_results["division"], result)
    
    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getRemResult")
    check_expected_result("reminder", expected_results["reminder"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getMuxResult")
    check_expected_result("mux", expected_results["mux"], result)

    result = soda_helper.call_contract_view('PrecompilesMiscellaneousTestsContract.sol', "getOnboardOffboardResult")
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
        print(f'Test transfer Failed.')
    
    check_expected_result("transfer", expected_results["transfer_a"], new_a)
    check_expected_result("transfer", expected_results["transfer_b"], new_b)
    
    new_a, new_b, res = soda_helper.call_contract_view('PrecompilesTransferScalarTestsContract.sol', "getResults")
    if not res:
        print(f'Test transfer Failed.')
    
    check_expected_result("transfer scalar", expected_results["transfer_a"], new_a)
    check_expected_result("transfer scalar", expected_results["transfer_b"], new_b)

    andRes, orRes, xorRes, notRes, eqRes, neqRes, muxRes, onboardRes = soda_helper.call_contract_view('PrecompilesMiscellaneous1TestsContract.sol', "getBooleanResults")
    check_expected_result("boolean_and", expected_results["boolean_and"], andRes)
    check_expected_result("boolean_or", expected_results["boolean_or"], orRes)
    check_expected_result("boolean_xor", expected_results["boolean_xor"], xorRes)
    check_expected_result("boolean_not", expected_results["boolean_not"], notRes)
    check_expected_result("boolean_equal", expected_results["boolean_equal"], eqRes)
    check_expected_result("boolean_notEqual", expected_results["boolean_notEqual"], neqRes)
    check_expected_result("boolean_mux", expected_results["boolean_mux"], muxRes)
    check_expected_result("boolean_onboard_offboard", expected_results["boolean_onboard_offboard"], onboardRes)

# Main test function
def run_tests(soda_helper, a, b, shift, bit, numBits, bool_a, bool_b):
    expected_results = {}

    # Test Addition
    print("Run addition test...")
    test_addition(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b, a + b)
    expected_results["addition"] = a+b
    
    # Test Subtraction
    print("Run subtraction test...")
    test_subtraction(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b, a - b)
    expected_results["subtract"] = a-b

    # Test Multiplication
    print("Run multiplication test...")
    test_multiplication(soda_helper, 'PrecompilesArythmeticTestsContract.sol', a, b, a * b)
    expected_results["multiplication"] = a*b

    # Test Division
    print("Run division test...")
    test_division(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, b, a / b)
    expected_results["division"] = a/b

    # Test Remainder
    print("Run remainder test...")
    test_remainder(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, b, a % b)
    expected_results["reminder"] = a%b

    # Test Mux
    print("Run mux test...")
    test_mux(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', bit, a, b, a if bit == 0 else b)
    expected_results["mux"] = a if bit == 0 else b

    # Test Offboard_Onboard
    print("Run offboard_Onboard test...")
    test_offboardOnboard(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', a, a)
    expected_results["onboard_offboard"] = a

    # test not
    print("Run not test...")
    test_not(soda_helper, 'PrecompilesMiscellaneousTestsContract.sol', bit, not bit)
    expected_results["not"] = not bit

    # Test Bitwise AND
    print("Run and test...")
    test_bitwise_and(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b, a & b)
    expected_results["and"] = a & b

    # Test Bitwise OR
    print("Run or test...")
    test_bitwise_or(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b, a | b)
    expected_results["or"] = a | b

    # Test Bitwise XOR
    print("Run xor test...")
    test_bitwise_xor(soda_helper, 'PrecompilesBitwiseTestsContract.sol', a, b, a ^ b)
    expected_results["xor"] = a ^ b

    # Test Bitwise Shift Left
    print("Run shift left test...")
    test_bitwise_shift_left(soda_helper, 'PrecompilesShiftTestsContract.sol', a, shift, (a << shift) & 0xFF, (a << shift) & 0xFFFF, (a << shift) & 0xFFFFFFFF, (a << shift) & 0xFFFFFFFFFFFFFFFF) # Calculate the result in 8, 16, 32, and 64 bit
    expected_results["shift_left8"] = (a << shift) & 0xFF
    expected_results["shift_left16"] = (a << shift) & 0xFFFF
    expected_results["shift_left32"] = (a << shift) & 0xFFFFFFFF
    expected_results["shift_left64"] = (a << shift) & 0xFFFFFFFFFFFFFFFF

    # Test Bitwise Shift Right
    print("Run shift right test...")
    test_bitwise_shift_right(soda_helper, 'PrecompilesShiftTestsContract.sol', a, shift, a >> shift)
    expected_results["shift_right"] = a >> shift

    # Test Min
    print("Run min test...")
    test_min(soda_helper, 'PrecompilesMinMaxTestsContract.sol', a, b, min(a, b))
    expected_results["min"] = min(a, b)

    # Test Max
    print("Run max test...")
    test_max(soda_helper, 'PrecompilesMinMaxTestsContract.sol', a, b, max(a, b))
    expected_results["max"] = max(a, b)

    # Test Equality
    print("Run equality test...")
    test_eq(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b, a == b)
    expected_results["eq"] = (a == b)

    # Test Not Equal
    print("Run not equal test...")
    test_ne(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b, a != b)
    expected_results["ne"] = (a != b)

    # Test Greater Than or Equal
    print("Run greater than or equal test...")
    test_ge(soda_helper, 'PrecompilesComparison2TestsContract.sol', a, b, a >= b)
    expected_results["ge"] = (a >= b)

    # Test Greater Than
    print("Run greater than test...")
    test_gt(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b, a > b)
    expected_results["gt"] = (a > b)

    # Test Less Than or Equal
    print("Run less than or equal test...")
    test_le(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b, a <= b)
    expected_results["le"] = (a <= b)

    # Test Less Than
    print("Run less than test...")
    test_lt(soda_helper, 'PrecompilesComparison1TestsContract.sol', a, b, a < b)
    expected_results["lt"] = (a < b)

    # Test Transfer
    print("Run transfer test...")
    test_transfer(soda_helper, 'PrecompilesTransferTestsContract.sol', a, b, b, a - b, b + b)
    expected_results["transfer_a"] = a - b
    expected_results["transfer_b"] = b + b
    
    # Test Transfer scalar
    print("Run transfer scalar test...")
    test_transfer(soda_helper, 'PrecompilesTransferScalarTestsContract.sol', a, b, b, a - b, b + b)

    # Test boolean functions
    test_boolean(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', bool_a, bool_b, bit)
    expected_results["boolean_and"] = bool_a and bool_b
    expected_results["boolean_or"] = bool_a or bool_b
    expected_results["boolean_xor"] = bool_a ^ bool_b
    expected_results["boolean_not"] = not bool_a
    expected_results["boolean_equal"] = bool_a == bool_b
    expected_results["boolean_notEqual"] = bool_a != bool_b
    expected_results["boolean_mux"] = bool_b if bit else bool_a
    expected_results["boolean_onboard_offboard"] = bool_a

    checkResults(soda_helper, expected_results)

    # These test cannot be run in the current testnet stage
    # TODO add them after the MPC is running
    # test getUserKey
    # private_key, public_key = generate_rsa_keypair()
    # test_getUserKey(soda_helper, 'PrecompilesOffboardToUserKeyTestContract.sol', a, a, public_key)

    # test random
    # test_random(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol')

    # test random bounded bits
    # test_randomBoundedBits(soda_helper, 'PrecompilesMiscellaneous1TestsContract.sol', numBits)

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
