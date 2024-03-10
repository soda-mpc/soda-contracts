import os
from eth_account import Account
import sys
sys.path.append('soda-sdk')
from python.crypto import decrypt, prepare_IT, block_size
from lib.python.soda_web3_helper import SodaWeb3Helper, REMOTE_HTTP_PROVIDER_URL

FILE_NAME = 'PrivateERC20Contract.sol'
FILE_PATH = 'examples/contracts/'
INITIAL_BALANCE = 500000000

def decrypt_value(my_CTBalance, user_key):
    
    # Convert ct to bytes (big-endian)
    byte_array = my_CTBalance.to_bytes(32, byteorder='big')

    # Split ct into two 128-bit arrays r and cipher
    cipher = byte_array[:block_size]
    r = byte_array[block_size:]

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

def execute_and_check_balance(soda_helper, account, contract, function, user_key, name, expected_balance):
    receipt = soda_helper.call_contract_function_transaction("private_erc20", function)
    if receipt is None:
        print("Failed to call the transaction function")
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
    # Get the account private key from the environment variable
    private_key = os.environ.get('SIGNING_KEY')
    account = Account.from_key(private_key)

    soda_helper = SodaWeb3Helper(private_key, REMOTE_HTTP_PROVIDER_URL)

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, "private_erc20")
    if not success:
        print("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("private_erc20", constructor_args=["Soda", "SOD", INITIAL_BALANCE])
    if receipt is None:
        print("Failed to deploy the contract")

    contract = soda_helper.get_contract("private_erc20")
    

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
    execute_and_check_balance(soda_helper, account, contract, function, user_key, 'transfer', INITIAL_BALANCE - plaintext_integer)

    print("************* Transfer clear ", plaintext_integer, " to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.contractTransferClear(alice_address.address, plaintext_integer)
    execute_and_check_balance(soda_helper, account, contract, function, user_key, 'contract transfer clear', INITIAL_BALANCE - 2*plaintext_integer)

    print("************* Transfer IT ", plaintext_integer, " to Alice *************")
    # In order to generate the input text, we need to use some data of the function. 
    # For example, the address of the user, the address of the contract and also the function signature.
    # To simplify the process of obtaining the function signature, we use a dummy function with placeholder inputs.
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
    execute_and_check_balance(soda_helper, account, contract, function, user_key, 'transfer IT', INITIAL_BALANCE - 3*plaintext_integer)

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice without allowance *************")
    # Trying to transfer 5 SOD to Alice. There is no allowance, transfer should fail
    function = contract.functions.transferFrom(account.address, alice_address.address, plaintext_integer, True)
    execute_and_check_balance(soda_helper, account, contract, function, user_key, 'transfer from', INITIAL_BALANCE - 3*plaintext_integer)

    print("************* Approve ", plaintext_integer*10, " to my address *************")
    # Set allowance for this account
    function = contract.functions.approveClear(account.address, plaintext_integer*10)
    soda_helper.call_contract_function_transaction("private_erc20", function)
    # Get my allowance to check that the allowance is correct
    check_allowance(account, contract, user_key, plaintext_integer*10)

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.transferFrom(account.address, alice_address.address, plaintext_integer, True)
    execute_and_check_balance(soda_helper, account, contract, function, user_key, 'transfer from', INITIAL_BALANCE - 4*plaintext_integer)

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.contractTransferFromClear(account.address, alice_address.address, plaintext_integer)
    execute_and_check_balance(soda_helper, account, contract, function, user_key, 'contract transfer from clear ', INITIAL_BALANCE - 5*plaintext_integer)

    print("************* Transfer IT ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.transferFrom(account.address, alice_address.address, dummyCT, dummySignature, False) # Dummy function
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(plaintext_integer, user_key, account, contract, func_sig, bytes.fromhex(private_key[2:]))
    # Create the real function using the prepared IT
    function = contract.functions.transferFrom(account.address, alice_address.address, ct, signature, False)
    execute_and_check_balance(soda_helper, account, contract, function, user_key, 'transfer from IT', INITIAL_BALANCE - 6*plaintext_integer)
    
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
    soda_helper.call_contract_function_transaction("private_erc20", function)

    print("************* Check my allowance *************")
    # Check that the allowance has changed to 50 SOD
    check_allowance(account, contract, user_key, 50)




if __name__ == "__main__":
    main()
