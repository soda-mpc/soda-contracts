import json
import os
import sys
from eth_account import Account
from solcx import compile_standard, install_solc, get_installed_solc_versions
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), '../../tools/python')))
from crypto import generate_rsa_keypair, decrypt_rsa, sign

SOLC_VERSION = '0.8.19'
FILE_PATH = 'GetUserKeyContract.sol'
PROVIDER_URL = 'http://localhost:7000'

def check_and_install_solc_version(solc_version):
    if solc_version not in get_installed_solc_versions():
        install_solc(solc_version)

def read_solidity_code(file_path):
    if not os.path.exists("../contracts/" + file_path):
        raise Exception(f"The file {file_path} does not exist")
    with open("../contracts/" + file_path, 'r') as file:
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
    construct_txn = contract.constructor().build_transaction({
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


def execute_transaction(w3, account, contract, function, gas_limit=2000000, gas_price='50'):
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


def main():
    check_and_install_solc_version(SOLC_VERSION)
    solidity_code = read_solidity_code(FILE_PATH)

    mpc_inst_path = "../../lib/solidity/MPCInst.sol"
    mpc_core_path = "../../lib/solidity/MpcCore.sol"
    compiled_sol = compile_solidity(SOLC_VERSION, FILE_PATH, solidity_code, mpc_inst_path, mpc_core_path)

    contract_name = FILE_PATH.split('.')[0]
    bytecode = compiled_sol['contracts'][FILE_PATH][contract_name]['evm']['bytecode']['object']
    contract_abi = json.loads(compiled_sol['contracts'][FILE_PATH][contract_name]['metadata'])['output']['abi']
    contract_bytecode = f'0x{bytecode}'

    w3 = Web3(HTTPProvider(PROVIDER_URL))
    if not w3.is_connected():
        print("Failed to connect to the node.")
        exit()

    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    signing_key = os.environ.get('SIGNING_KEY')
    account = Account.from_key(signing_key)
    w3.eth.default_account = account.address
    
    contract = deploy_contract(w3, account, contract_abi, contract_bytecode)

    # Generate new RSA key pair
    private_key, public_key = generate_rsa_keypair()
    # Sign the public key
    signedEK = sign(public_key, bytes.fromhex(signing_key[2:]))

    # Call the getUserKey function to get the encrypted AES key
    function = contract.functions.getUserKey(public_key, signedEK)
    execute_transaction(w3, account, contract, function)
    encryptedKey = contract.functions.getSavedUserKey().call({'from': account.address})
    
    # Decrypt the aes key using the RSA private key
    decrypted_aes_key = decrypt_rsa(private_key, encryptedKey)
    # Print the aes key
    print("user AES key:", decrypted_aes_key.hex())

    # Write the data to a .env file
    with open('../../.env', 'a') as f:
        f.write(f"export USER_KEY='{decrypted_aes_key.hex()}'\n")


if __name__ == "__main__":
    main()
