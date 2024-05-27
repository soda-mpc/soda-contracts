import os
from eth_account import Account
import sys
sys.path.append('soda-sdk')
from python.crypto import decrypt, prepare_IT, block_size
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter
from web3.exceptions import TransactionNotFound
from time import sleep

FILE_NAME = 'PrivateERC20Contract.sol'
FILE_PATH = 'examples/contracts/'
INITIAL_BALANCE = 500000000
NONCE = 0

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

def get_encrypted_balance(soda_helper, account, contract):
    function = contract.functions.balanceOf()
    receipt = soda_helper.call_contract_function_transaction("private_erc20", function)
    if receipt is None:
        print("Failed to call the transaction function")
    balance_events = contract.events.Balance().process_receipt(receipt)
    # Filter events for the specific address
    for event in balance_events:
        if event['args']['_owner'].lower() == account.address.lower():
            return event['args']['_balance']
    
    print("Failed to find balance of the account address in the transaction receipt.")
    return None

def execute_transaction(soda_helper, account, contract, function):
    gas_estimate = function.estimate_gas({
        'from': account.address,
    })
    print('Estimated Gas:', gas_estimate)
    global NONCE
    hash = soda_helper.call_contract_function_transaction_async("private_erc20", function, NONCE)
    NONCE += 1
    return hash

def check_balance(soda_helper, account, contract, user_key, name, expected_balance):
    
    # Get my encrypted balance, decrypt it and check if it matches the expected value
    my_CTBalance = get_encrypted_balance(soda_helper, account, contract)
    my_balance = decrypt_value(my_CTBalance, user_key)
    check_expected_result(name, expected_balance, my_balance)

def check_allowance(soda_helper, account, contract, user_key, expected_allowance):
    # Get my encrypted allowance, decrypt it and check if it matches the expected value
    function = contract.functions.allowance(account.address, account.address)
    receipt = soda_helper.call_contract_function_transaction("private_erc20", function)
    if receipt is None:
        print("Failed to call the transaction function")

    allowance_events = contract.events.Allowance().process_receipt(receipt)

    allowanceCT = None
    # Filter events for the specific address
    for event in allowance_events:
        if event['args']['_owner'].lower() == account.address.lower():
            allowanceCT = event['args']['_allowance']
    
    if allowanceCT is None:
        print("Failed to find the allowance of the account address in the transaction receipt.")

    allowance = decrypt_value(allowanceCT, user_key)
    check_expected_result('allowance', expected_allowance, allowance)

def check_expected_result(name, expected_result, result):
    if result == expected_result:
        print(f'Test {name} succeeded: {result}')
    else:
        raise ValueError(f'Test {name} failed. Expected: {expected_result}, Actual: {result}')

def main(provider_url: str):
    # Get the account private key from the environment variable
    private_key = os.environ.get('SIGNING_KEY')
    account = Account.from_key(private_key)

    soda_helper = SodaWeb3Helper(private_key, provider_url)

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, "private_erc20")
    if not success:
        print("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("private_erc20", constructor_args=["Soda", "SOD", INITIAL_BALANCE])
    if receipt is None:
        print("Failed to deploy the contract")

    contract = soda_helper.get_contract("private_erc20")
    
    global NONCE
    NONCE = soda_helper.get_current_nonce()

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

    # Generate a new Ethereum account for Alice
    alice_address = Account.create()

    plaintext_integer = 5

    print("************* Transfer clear ", plaintext_integer, " to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.transfer(alice_address.address, plaintext_integer, True)
    execute_transaction(soda_helper, account, contract, function)

    print("************* Transfer clear ", plaintext_integer, " to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.contractTransferClear(alice_address.address, plaintext_integer)
    execute_transaction(soda_helper, account, contract, function)

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
    execute_transaction(soda_helper, account, contract, function)

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice without allowance *************")
    # Trying to transfer 5 SOD to Alice. There is no allowance, transfer should fail
    function = contract.functions.transferFrom(account.address, alice_address.address, plaintext_integer, True)
    execute_transaction(soda_helper, account, contract, function)

    print("************* Approve ", plaintext_integer*10, " to my address *************")
    # Set allowance for this account
    function = contract.functions.approveClear(account.address, plaintext_integer*10)
    soda_helper.call_contract_function_transaction_async("private_erc20", function, NONCE)
    NONCE += 1

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.transferFrom(account.address, alice_address.address, plaintext_integer, True)
    execute_transaction(soda_helper, account, contract, function)

    print("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.contractTransferFromClear(account.address, alice_address.address, plaintext_integer)
    execute_transaction(soda_helper, account, contract, function)

    print("************* Transfer IT ", plaintext_integer, " from my account to Alice *************")
    # Transfer 5 SOD to Alice
    function = contract.functions.transferFrom(account.address, alice_address.address, dummyCT, dummySignature, False) # Dummy function
    func_sig = get_function_signature(function.abi) # Get the function signature
    # Prepare the input text for the function
    ct, signature = prepare_IT(plaintext_integer, user_key, account, contract, func_sig, bytes.fromhex(private_key[2:]))
    # Create the real function using the prepared IT
    function = contract.functions.transferFrom(account.address, alice_address.address, ct, signature, False)
    tx_hash = execute_transaction(soda_helper, account, contract, function)
    tx_receipt = None
    while tx_receipt is None:
        try:
            tx_receipt = soda_helper.web3.eth.get_transaction_receipt(tx_hash.hex())
        except TransactionNotFound as e:
            pass
        sleep(1)

    print("************* Check my balance *************")
    check_balance(soda_helper, account, contract, user_key, 'balanceOf', INITIAL_BALANCE - 6*plaintext_integer)

    print("************* Check my allowance *************")
    # Check that the allowance has changed to 50 SOD
    check_allowance(soda_helper, account, contract, user_key, plaintext_integer*7)




if __name__ == "__main__":
    url = parse_url_parameter()
    if (url is not None):
        main(url)
