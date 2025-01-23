import logging
import os
from eth_account import Account
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter
from soda_python_sdk import generate_rsa_keypair, sign, recover_user_key, prepare_IT

SIGNATURE_SIZE = 65

SOLIDITY_FILES = ['onboardUser/contracts/GetUserKeyContract.sol',
                  'tests/contracts/PrecompilesMiscellaneous1TestsContract.sol',
                  'tests/contracts/PrecompilesOffboardToUserKeyTestContract.sol',
                  'tests/contracts/MalformedInputs.sol']

def getUserKeyShares(account, contract, receipt):
    """
    This function retrieves the key shares of a user from a transaction receipt. It processes the receipt 
    to get the UserKey events, then iterates through these events to find the ones that match the provided 
    account address. If it finds matching events, it extracts the key shares from these events. If it doesn't 
    find any matching events, it prints an error message.

    @param {object} account - The account object, which includes the user's address.
    @param {object} contract - The contract object, which includes the contract's events.
    @param {object} receipt - The transaction receipt to process.

    @return {tuple} A tuple containing the two key shares, or (None, None) if no matching events were found.
    """
    user_key_events = contract.events.UserKey().process_receipt(receipt)

    key_0_share = None
    key_1_share = None
    # Filter events for the specific address
    for event in user_key_events:
        if event['args']['_owner'].lower() == account.address.lower():
            key_0_share = event['args']['_keyShare0']
            key_1_share = event['args']['_keyShare1']
    
    if key_0_share is None or key_1_share is None:
        print("Failed to find the key shares of the account address in the transaction receipt.")

    return key_0_share, key_1_share

def generateRSAKeysAndSignature(signing_key):
    # Generate new RSA key pair
    private_key, public_key = generate_rsa_keypair()
    # Sign the public key
    signature = sign(public_key, bytes.fromhex(signing_key[2:]))

    return private_key, public_key, signature

def getUserKey(signing_key, soda_helper, contract_str):
    # Generate new RSA key pair and signature on the public key
    private_key, public_key, signature = generateRSAKeysAndSignature(signing_key)

    # Call the getUserKey function to get the encrypted AES shares
    receipt = soda_helper.call_contract_transaction(contract_str, "getUserKey", func_args=[public_key, signature])
    if receipt is None:
        raise Exception("Failed to call the transaction function")

    encryptedKey0, encryptedKey1 = getUserKeyShares(soda_helper.get_account(), soda_helper.get_contract(contract_str), receipt)

    # Recover the aes key using the RSA private key and the given shares
    return recover_user_key(private_key, encryptedKey0, encryptedKey1)
    
def get_function_signature(function_abi):
    # Extract the input types from the ABI
    input_types = ','.join([param['type'] for param in function_abi.get('inputs', [])])

    # Generate the function signature
    return f"{function_abi['name']}({input_types})"

def errorVerifyingSignatureTest(signing_key, soda_helper, conrtact_str):
    # Generate new RSA key pair and signature on the public key
    _, public_key, signature = generateRSAKeysAndSignature(signing_key)

    # change the signature last byte to 0x00
    wrong_signature = b'\x10' + signature[1:]

    # Call the getUserKey function to get the encrypted AES shares
    receipt = soda_helper.call_contract_transaction(conrtact_str, "getUserKey", func_args=[public_key, wrong_signature])
    
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test errorVerifyingSignature reverted as expected')
    else:
        raise ValueError(f'Test errorVerifyingSignature did not revert')
    

def errorEmptyInput_getUserKeyTest(signing_key, soda_helper, conrtact_str):
    # Generate new RSA key pair and signature on the public key
    _, public_key, signature = generateRSAKeysAndSignature(signing_key)

    # Create an empty input
    empty = bytes(0)

    # Call the getUserKey function to get the encrypted AES shares
    receipt = soda_helper.call_contract_transaction(conrtact_str, "getUserKey", func_args=[public_key, empty])
    
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test empty signature in getUserKey reverted as expected')
    else:
        raise ValueError(f'Test empty signature in getUserKey did not revert')
    
    # Call the getUserKey function to get the encrypted AES shares
    receipt = soda_helper.call_contract_transaction(conrtact_str, "getUserKey", func_args=[empty, empty])
    
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test empty signature and ct in getUserKey reverted as expected')
    else:
        raise ValueError(f'Test empty signature and ct in getUserKey did not revert')
    

    # Call the getUserKey function to get the encrypted AES shares
    receipt = soda_helper.call_contract_transaction(conrtact_str, "getUserKey", func_args=[empty, signature])
    
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test empty ct in getUserKey reverted as expected')
    else:
        raise ValueError(f'Test empty ct in getUserKey did not revert')
    
def invalidSignatureTest(signing_key, soda_helper, contract_str):
    user_key_hex = os.environ.get('USER_KEY')
    user_aes_key = bytes.fromhex(user_key_hex)  
    
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
    ct, signature = prepare_IT(5, user_aes_key, Account.from_key(signing_key), contract, func_sig, bytes.fromhex(signing_key[2:]))
    
    # change the signature last byte to 0x00
    wrong_signature = b'\x10' + signature[1:]

    receipt = soda_helper.call_contract_transaction(contract_str, "validateCiphertextTest", func_args=[ct, ct, ct, ct, wrong_signature])
    
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test invalidSignature reverted as expected')
    else:
        raise ValueError(f'Test invalidSignature did not revert')

def emptyInput_validateCiphertextTest(signing_key, soda_helper, contract_str):
    user_key_hex = os.environ.get('USER_KEY')
    user_aes_key = bytes.fromhex(user_key_hex)  
    
    dummyCT = 0
    dummySignature = bytes(65)
    contract = soda_helper.get_contract(contract_str)
    function = contract.functions.validateCiphertextTest(dummyCT, dummyCT, dummyCT, dummyCT, dummySignature)
    func_sig = get_function_signature(function.abi) # Get the function signature
    
    # Prepare the input text for the function
    ct, signature = prepare_IT(5, user_aes_key, Account.from_key(signing_key), contract, func_sig, bytes.fromhex(signing_key[2:]))
    
    # Create an empty signature
    empty_signature = bytes(0)

    receipt = soda_helper.call_contract_transaction(contract_str, "validateCiphertextTest", func_args=[ct, ct, ct, ct, empty_signature])
    
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test empty signature in validateCiphertext reverted as expected')
    else:
        raise ValueError(f'Test empty signature in validateCiphertext did not revert')
    
    # Create an empty ct
    empty_ct = int(0)

    receipt = soda_helper.call_contract_transaction(contract_str, "validateCiphertextTest", func_args=[empty_ct, empty_ct, empty_ct, empty_ct, empty_signature])
    
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test empty signature and ct in validateCiphertext reverted as expected')
    else:
        raise ValueError(f'Test empty signature and ct in validateCiphertext did not revert')
    
    receipt = soda_helper.call_contract_transaction(contract_str, "validateCiphertextTest", func_args=[empty_ct, empty_ct, empty_ct, empty_ct, signature])
    
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test empty ct in validateCiphertext reverted as expected')
    else:
        raise ValueError(f'Test empty ct in validateCiphertext did not revert')
    
def malformedInputToDecryptTest(soda_helper, contract_str):

    receipt = soda_helper.call_contract_transaction(contract_str, "malformedLargeInputDecrypt")
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test malformed large inputs to decrypt reverted as expected')
    else:
        raise ValueError(f'Test malformed large inputs to decrypt did not revert')
    
    receipt = soda_helper.call_contract_transaction(contract_str, "malformedSmallInputDecrypt")
    if receipt is None:
        raise Exception("Failed to call the transaction function")
    
    if receipt.status == 0:
        print(f'Test malformed small inputs to decrypt reverted as expected')
    else:
        raise ValueError(f'Test malformed small inputs to decrypt did not revert')
    

def main(provider_url: str):

    signing_key = os.environ.get('SIGNING_KEY')

    soda_helper = SodaWeb3Helper(signing_key, provider_url)
    account = soda_helper.get_account()

    # Compile the contracts
    for file_name in SOLIDITY_FILES:
        success = soda_helper.setup_contract(file_name, file_name)
        if not success:
            raise Exception("Failed to set up the contract")

    # Deploy the contract
    receipts = soda_helper.deploy_multi_contracts(SOLIDITY_FILES, constructor_args=[])
    
    if len(receipts) != len(SOLIDITY_FILES):
        raise Exception("Failed to deploy the contracts")
    
    # Check revert on 'error verifying signature' error in getUserKey function
    errorVerifyingSignatureTest(signing_key, soda_helper, SOLIDITY_FILES[0])

    # Check revert on 'invalid signature' error in validateCiphertext function
    invalidSignatureTest(signing_key, soda_helper, SOLIDITY_FILES[1])

    # Check revert on empty signature or ct in validateCiphertext function
    emptyInput_validateCiphertextTest(signing_key, soda_helper, SOLIDITY_FILES[1])

    # Check revert on empty signature or ct in getUserKey function
    errorEmptyInput_getUserKeyTest(signing_key, soda_helper, SOLIDITY_FILES[0])
    
    # Check revert on wrong input size
    malformedInputToDecryptTest(soda_helper, 'tests/contracts/MalformedInputs.sol')

if __name__ == "__main__":
    url = parse_url_parameter()
    if (url is not None):
        try:
            main(url)
        except Exception as e:
            logging.error("An error occurred: %s", e)
            raise e
            
