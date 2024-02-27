import json
import os
import sys

from eth_account import Account
from solcx import compile_standard, install_solc, get_installed_solc_versions
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), '../tools/python')))
from crypto import generate_rsa_keypair, decrypt_rsa, encrypt_rsa, sign, decrypt



print("Current working directory:", os.getcwd())

# Specify the Solidity version
SOLC_VERSION = '0.8.19'
# Path to the Solidity file
FILE_PATH = 'PrecompilesOffboardToUserKeyTestContract.sol'
# The exposed port for the local node 
PROVIDER_URL = 'http://localhost:7000'
# The ley corresponding to the deployer account
PRIVATE_KEY = "0x2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"

# Check if the solc version is already installed, if not, install it
if SOLC_VERSION not in get_installed_solc_versions():
    install_solc(SOLC_VERSION)

# Ensure the file path is valid
if not os.path.exists(FILE_PATH):
    raise Exception(f"The file {FILE_PATH} does not exist")

# Read the Solidity source code from the file
with open(FILE_PATH, 'r') as file:
    solidity_code = file.read()

# Define the file paths for your Solidity files
mpc_inst_path = "../solidity_lib/MPCInst.sol"
mpc_core_path = "../solidity_lib/MpcCore.sol"

# Use the file paths in the compile_standard function in the desired order
compiled_sol = compile_standard({
    "language": "Solidity",
    "sources": {
        "MPCInst.sol": {"urls": [mpc_inst_path]},
        "MpcCore.sol": {"urls": [mpc_core_path]},
        FILE_PATH: {"content": solidity_code},
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
allow_paths=[".", "../solidity_lib"]
)


# Extract bytecode and ABI
contract_name = FILE_PATH.split('.')[0]  # Assumes the contract name is the file name
bytecode = compiled_sol['contracts'][FILE_PATH][contract_name]['evm']['bytecode']['object']
contract_abi = json.loads(compiled_sol['contracts'][FILE_PATH][contract_name]['metadata'])['output']['abi']

contract_bytecode = f'0x{bytecode}'  

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

# Contract object
contract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)

# Build transaction
construct_txn = contract.constructor().build_transaction({
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

print(f'Contract Deployed At Address: {tx_receipt.contractAddress}')

# Create the contract instance
contract = w3.eth.contract(address=tx_receipt.contractAddress, abi=contract_abi)

private_key, public_key = generate_rsa_keypair()

signedEK = sign(public_key, bytes.fromhex("2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"))

# Prepare the transaction
transaction = contract.functions.getUserKeyTest(public_key, signedEK, account.address).build_transaction({
    'from': account.address,
    'chainId': 50505050,
    'gas': 2000000,
    'gasPrice': w3.to_wei('50', 'gwei'),
    'nonce': w3.eth.get_transaction_count(account.address),
})

# Sign the transaction
signed_txn = w3.eth.account.sign_transaction(transaction, private_key=PRIVATE_KEY)

# Send the transaction
txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)

# Wait for the transaction to be mined
txn_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)

print(f'Transaction successful with hash: {txn_hash.hex()}')

# Call a function
x_0 = contract.functions.getX().call()

# Print the result of the function call
print("Function call result:", x_0)

# Call a function
function_call_result = contract.functions.getUserKey().call()

decrypted_aes_key = decrypt_rsa(private_key, function_call_result)
# Print the aes key
print("user AES key:", decrypted_aes_key.hex())

# Get the ct
ct = contract.functions.getCt().call()
# Convert ct to bytes (big-endian)
byte_array = ct.to_bytes(32, byteorder='big')

# Split ct into two 128-bit arrays r and cipher
cipher = byte_array[:16]
r = byte_array[16:]

# Decrypt the cipher
decrypted_message = decrypt(decrypted_aes_key, r, cipher)

# Print the decrypted cipher
x = int.from_bytes(decrypted_message, 'big')
print("Decrypted x:", x)


# Check that the result of both offboard functions is the same
if x != x_0:
    print("Failure")
    raise ValueError("Decrypted value does not match expected value")
else:
    print("Success")


