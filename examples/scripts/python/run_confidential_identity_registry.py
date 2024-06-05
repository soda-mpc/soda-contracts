import os
from eth_account import Account
import sys

sys.path.append('soda-sdk')
from python.crypto import prepare_IT
from lib.python.soda_web3_helper import SodaWeb3Helper, parse_url_parameter, get_function_signature, decrypt_value_int, \
    execute_transaction, extract_event_value

FILE_NAME = 'ConfidentialIdentityRegistry.sol'
FILE_PATH = 'examples/contracts/'
INITIAL_BALANCE = 500000000


def main(provider_url: str):
    # Get the account private key from the environment variable
    private_key = os.environ.get('SIGNING_KEY')
    owner = Account.from_key(private_key)
    print(f'Owner Address: {owner.address}')

    user_key_hex = os.environ.get('USER_KEY')
    user_key = bytes.fromhex(user_key_hex)

    user1 = Account.create()
    user2 = Account.create()

    soda_helper = SodaWeb3Helper(private_key, provider_url)

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + FILE_NAME, 'confidential_identity_registry')
    if not success:
        print('Failed to set up the contract')

    # Deploy the contract
    receipt = soda_helper.deploy_contract('confidential_identity_registry', constructor_args=[owner.address])
    if receipt is None:
        print('Failed to deploy the contract')

    contract = soda_helper.get_contract('confidential_identity_registry')
    print(f'Contract Address: {contract.address}')

    print('************* Contract setup *************')

    # register owner as registrar
    function = contract.functions.addRegistrar(owner.address, 2)
    execute_transaction(soda_helper, owner, 'confidential_identity_registry', function)

    # register owner in the smart contract
    function = contract.functions.addDid(owner.address)
    execute_transaction(soda_helper, owner, 'confidential_identity_registry', function)

    # register user1 in the smart contract
    function = contract.functions.addDid(user1.address)
    execute_transaction(soda_helper, owner, 'confidential_identity_registry', function)

    # register user2 in the smart contract
    function = contract.functions.addDid(user2.address)
    execute_transaction(soda_helper, owner, 'confidential_identity_registry', function)

    print('************* View functions *************')
    owner_result = contract.functions.owner().call({'from': owner.address})
    print('Function call result owner:', owner_result)

    registrar = contract.functions.registrars(owner.address).call()
    print(f'Owner Registrar id: {registrar}')

    print('************* Simple Identity Age attribute test *************')
    age = 21
    dummy_ct = 0
    dummy_signature = bytes(65)
    # register can set encrypted identity attribute for user. e.g. age
    function = contract.functions.setIdentifier(user1.address, 'age', dummy_ct, dummy_signature)
    func_sig = get_function_signature(function.abi)
    print('Age plaintext:', age)

    # encrypt the age using the user key
    ct, signature = prepare_IT(age, user_key, owner, contract, func_sig, bytes.fromhex(private_key[2:]))
    print(f'Age CT: {ct}')

    # set the encrypted age in the contract
    function = contract.functions.setIdentifier(user1.address, 'age', ct, signature)
    execute_transaction(soda_helper, owner, 'confidential_identity_registry', function)

    # owner can read the encrypted identity attribute value for any user
    function = contract.functions.getIdentifier(user1.address, 'age')
    receipt = soda_helper.call_contract_function_transaction('confidential_identity_registry', function)
    if receipt is None:
        print('Failed to read the encrypted age attribute for user1')

    # encrypted value is stored in the event log
    # Filter events for the specific address
    def filter_func(event):
        return event['args']['_reader'].lower() == owner.address.lower() and event['args']['_identifier'] == 'age'

    age_encrypted = extract_event_value(contract, receipt, filter_func, target_attribute='_value')

    print(f'Age encrypted: {age_encrypted}')
    age_decrypted = decrypt_value_int(age_encrypted, user_key)
    print(f'Age decrypted: {age_decrypted}')
    assert age == age_decrypted, f'Age {age} does not match decrypted age {age_decrypted}'

    print('************* Permissions test *************')
    print("User can't read the encrypted identity attribute value without permission")

    # send some native currency to user2 to execute the transaction
    soda_helper.transfer_native_currency(user2.address, 0.1, is_async=False, account=owner)

    # user2 can't read the encrypted identity attribute value without permission
    function = contract.functions.getIdentifier(user1.address, 'age')
    receipt = soda_helper.call_contract_function_transaction('confidential_identity_registry', function, account=user2)
    if receipt is None:
        print('Failed to read the encrypted age attribute for user1')

    def filter_func(event):
        return event['args']['_reader'].lower() == user2.address.lower() and event['args']['_identifier'] == 'age'

    age_encrypted = extract_event_value(contract, receipt, filter_func, target_attribute='_value')
    assert age_encrypted is None, f'User2 should not be able to read the encrypted age'


if __name__ == "__main__":
    url = parse_url_parameter()
    if url is not None:
        main(url)
