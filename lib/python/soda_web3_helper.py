import os
import json
from web3.middleware import geth_poa_middleware
from eth_account import Account
from web3 import Web3
from solcx import compile_standard, install_solc, get_installed_solc_versions
import argparse

LOCAL_PROVIDER_URL = 'http://localhost:7000'
REMOTE_HTTP_PROVIDER_URL = 'https://node.sodalabs.net' 
SOLC_VERSION = '0.8.19'
DEFAULT_GAS_PRICE = 10
DEFAULT_GAS_LIMIT = 10000000
DEFAULT_CHAIN_ID = 50505050

def parse_url_parameter():
    parser = argparse.ArgumentParser(description='Get URL')
    parser.add_argument('provider_url', type=str, help='The provider url')
    args = parser.parse_args()
    if args.provider_url == "Local":
        return LOCAL_PROVIDER_URL
    elif args.provider_url == "Remote":
        return REMOTE_HTTP_PROVIDER_URL
    else:
        print("Invalid provider url")
        return None

class SodaWeb3Helper:
    def __init__(self, private_key_string, http_provider_url):
        self.private_key = private_key_string
        self.account = Account.from_key(private_key_string)
        print(f'Account address is {self.account.address}')
        
        self.web3 = Web3(Web3.HTTPProvider(http_provider_url))
        self.web3.eth.default_account = self.account.address
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0) 
        if not self.web3.is_connected():
            raise Exception("Failed to connect to the node.")
        print(f'Connected to the node at {http_provider_url}')
        
        self.contracts = {}
        print('SodaWeb3Helper initialized')
        
    def setup_contract(self, contract_path, contract_id, overwrite=False, 
                       mpc_inst_path="lib/solidity/MpcInterface.sol", 
                       mpc_core_path="lib/solidity/MpcCore.sol"):
        
        if contract_id in self.contracts and not overwrite:
            print(f"Contract with id {contract_id} already exists. Use the 'overwrite' parameter to overwrite it.")
            return False
        
        try:
            contract_bytecode, contract_abi = compile_contract(contract_path, mpc_inst_path, mpc_core_path)
        except Exception as e:
            print(f"Failed to compile the contract: {e}")
            return False
        
        self.contracts[contract_id] = self.web3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
        return True

    def get_contract(self, contract_id):
        if contract_id not in self.contracts:
            print(f"Contract with id {contract_id} does not exist. Use the 'setup_contract' method to set it up.")
            return None
        return self.contracts[contract_id]

    def get_account(self):
        return self.account

    
    def deploy_contract(self, 
                        contract_id, 
                        gas_limit=DEFAULT_GAS_LIMIT, 
                        gas_price=DEFAULT_GAS_PRICE, 
                        chain_id=DEFAULT_CHAIN_ID, 
                        constructor_args=[],
                        account=None):

        if account is None:
            account = self.account
        
        func_to_call = self.contracts[contract_id].constructor
        construct_txn = self._build_transaction(func_to_call, gas_limit, gas_price, chain_id, constructor_args, account)
        receipt = self._sign_and_send_transaction(construct_txn, account)
        if receipt is not None:
            print(f"Contract deployed at address: {receipt.contractAddress}")
            self.contracts[contract_id] = self.web3.eth.contract(
                address=receipt.contractAddress, 
                abi=self.contracts[contract_id].abi,
                bytecode=self.contracts[contract_id].bytecode)
        return receipt
    
    def call_contract_view(self, contract_id, func_name, func_args=[]):
        if contract_id not in self.contracts:
            print(f"Contract with id {contract_id} does not exist. Use the 'setup_contract' method to set it up.")
            return None
        
        contract = self.contracts[contract_id]
        func = getattr(contract.functions, func_name)
        return func(*func_args).call()
    
    def call_contract_transaction(self, 
                                  contract_id, 
                                  func_name, 
                                  gas_limit=DEFAULT_GAS_LIMIT, 
                                  gas_price=DEFAULT_GAS_PRICE, 
                                  chain_id=DEFAULT_CHAIN_ID, 
                                  func_args=[], 
                                  account=None):
        if account is None:
            account = self.account

        if contract_id not in self.contracts:
            print(f"Contract with id {contract_id} does not exist. Use the 'setup_contract' method to set it up.")
            return None
        
        func_to_call = getattr(self.contracts[contract_id].functions, func_name)
        transaction = self._build_transaction(func_to_call, gas_limit, gas_price, chain_id, func_args, account)
        
        return self._sign_and_send_transaction(transaction, account)

    def call_contract_function_transaction(self, 
                                  contract_id, 
                                  func, 
                                  gas_limit=DEFAULT_GAS_LIMIT, 
                                  gas_price=DEFAULT_GAS_PRICE, 
                                  chain_id=DEFAULT_CHAIN_ID, 
                                  account=None):
        if account is None:
            account = self.account
        
        if contract_id not in self.contracts:
            print(f"Contract with id {contract_id} does not exist. Use the 'setup_contract' method to set it up.")
            return None
        
        transaction = self._build_function_transaction(func, gas_limit, gas_price, chain_id, account)
        
        return self._sign_and_send_transaction(transaction, account)
    
    def generate_random_account(self):
        return Account.create()
    
    def get_native_currency_balance(self, address):
        if not self.validate_address(address)['valid']:
            print(f"Invalid address: {address}")
            return None
        
        return self.web3.eth.get_balance(address)
    
    def validate_address(self, address):
        return {'valid': Web3.is_address(address), 'safe': Web3.to_checksum_address(address)}  
    
    def transfer_native_currency(self, 
                                 to_address, 
                                 amount, 
                                 gas_limit=21000, 
                                 gas_price=DEFAULT_GAS_PRICE, 
                                 chain_id=DEFAULT_CHAIN_ID,
                                 account=None):

        if account is None:
            account = self.account
        
        if not self.validate_address(to_address)['safe']:
            print(f"Invalid address: {to_address}")
            return None
        
        transaction = {
            'to': to_address,
            'value': self.web3.to_wei(amount, 'ether'),
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': self.web3.eth.get_transaction_count(account.address),
            'chainId': chain_id
        }
        return self._sign_and_send_transaction(transaction, account)
    
    def convert_sod_to_wei(self, amount):
        return self.web3.to_wei(amount, 'ether')
    
    def convert_gwei_to_wei(self, amount):
        return self.web3.to_wei(amount, 'gwei')
    
    def wei_to_sod(self, amount):
        return self.web3.from_wei(amount, 'ether')
    
    def _build_transaction(self, func, gas_limit, gas_price, chain_id, tx_args=[], account=None):
        if account is None:
            account = self.account

        return func(*tx_args).build_transaction({
            'from': account.address,
            'chainId': chain_id,
            'nonce': self.web3.eth.get_transaction_count(account.address),
            'gas': gas_limit,
            'gasPrice': self.web3.to_wei(gas_price, 'wei')
        })  
    
    def _build_function_transaction(self, func, gas_limit, gas_price, chain_id, account=None):
        if account is None:
            account = self.account

        return func.build_transaction({
            'from': account.address,
            'chainId': chain_id,
            'nonce': self.web3.eth.get_transaction_count(account.address),
            'gas': gas_limit,
            'gasPrice': self.web3.to_wei(gas_price, 'wei')
        })  
    
    def _sign_and_send_transaction(self, transaction, account):
        if account is None:
            account = self.account
        try:
            signed_txn = self.web3.eth.account.sign_transaction(transaction, account._private_key)
        except Exception as e:
            print(f"Failed to sign the transaction: {e}")
            return None

        try:
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        except Exception as e:
            print(f"Failed to send the transaction: {e}")
            return None

        try:
            tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        except Exception as e:
            print(f"Failed to wait for the transaction receipt: {e}")
            return None

        return tx_receipt
    
    def send_signed_tx(self, raw_tx):
        try:
            return self.web3.eth.send_raw_transaction(raw_tx)
        except Exception as e:
            print(f"Failed to send the transaction: {e}")
            return None
    
def load_contract(file_path):
    # Ensure the file path is valid
    if not os.path.exists(file_path):
        raise Exception(f"The file {file_path} does not exist")

    # Read the Solidity source code from the file
    with open(file_path, 'r') as file:
        return file.read()

def compile_contract(file_path, mpc_inst_path="lib/solidity/MpcInterface.sol", mpc_core_path="lib/solidity/MpcCore.sol"):
    print(f'Current PWD: {os.getcwd()}')
    print(f'MPC INST {mpc_inst_path}')
    print(f'MPC CORE {mpc_core_path}')
    if SOLC_VERSION not in get_installed_solc_versions():
        install_solc(SOLC_VERSION)
        
    contract_name = os.path.basename(file_path).split('.')[0]
    print(f"Compiling {contract_name}...")
    
    solidity_code = load_contract(file_path)
    
    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": {
            "MpcInterface.sol": {"urls": [mpc_inst_path]},
            "MpcCore.sol": {"urls": [mpc_core_path]},
            file_path: {"content": solidity_code},
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
    allow_paths=[mpc_inst_path, mpc_core_path, file_path]
    )

    bytecode = compiled_sol['contracts'][file_path][contract_name]['evm']['bytecode']['object']
    contract_abi = json.loads(compiled_sol['contracts'][file_path][contract_name]['metadata'])['output']['abi']

    contract_bytecode = f'0x{bytecode}'
    
    return contract_bytecode, contract_abi
