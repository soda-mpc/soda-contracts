from soda_web3_helper import SodaWeb3Helper, DEFAULT_GAS_PRICE, REMOTE_HTTP_PROVIDER_URL

PRIVATE_KEY = "0x2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"
RECEIVER_ADDRESS = "0xc41Ba88D12f4E1869E287a909aD3D535Ba1FDf80"

# This is a simple example of how to use the SodaWeb3Helper class to interact
# with the Soda network. The example consists of two functions: transfer_native_currency
# and get_native_currency_balance.  
def transfer_transaction(soda_helper):
    # We first make sure we have a funded account
    sender_balance = soda_helper.get_native_currency_balance(soda_helper.account.address)
    if sender_balance is None:
        print("Failed to get the balance of the account")
        return
    print(f"Balance of the account: {sender_balance}")
    # We then transfer some native currency to a random account
    receiver_account = soda_helper.generate_random_account()
    amount_to_transfer = 2.4  # in SOD, an ether-like unit
    receipt = soda_helper.transfer_native_currency(receiver_account.address, amount_to_transfer)
    # We check the balance of the accounts after the transfer is complete
    receiver_balance = soda_helper.get_native_currency_balance(receiver_account.address)
    total_gas_cost = receipt.gasUsed * soda_helper.convert_gwei_to_wei(DEFAULT_GAS_PRICE)
    expected_balance = sender_balance - total_gas_cost - soda_helper.convert_sod_to_wei(amount_to_transfer)
    assert expected_balance == soda_helper.get_native_currency_balance(soda_helper.account.address)
    print(f"Balance of the sender account: {receiver_balance}")
    assert receiver_balance == soda_helper.convert_sod_to_wei(amount_to_transfer)
    print(f"Balance of the receiver account: {receiver_balance}")

# This is a more complex example of how to use the SodaWeb3Helper class to deploy and interact
# with a contract. The example consists of:
# 1. Setting up a contract - this will compile the contract and extract the bytecode and ABI. It is separated
#    from the deployment of the contract to allow for interacting with previously deployed contracts.
#    (by compiling and extracting the bytecode and ABI and saving it under some ID)
# 2. Deploying the contract - very straight forward, it deployed a previously set up contract with an arbitrary
#    number of constructor arguments.
# 3. Calling a view function of the contract - the function is specified by name and an arbitrary number of arguments
#    can be passed to it. 
# 4. Calling a transaction function of the contract - same as the view function, but it this function returns a
#    transaction receipt after the transaction is mined.
def contract_example(soda_helper):
    # We set up the contract - this will compile the contract and extract the bytecode and ABI.
    # The contract is not deployed yet, rather the compiled contract is saved under it's id (string)
    contract_path = "../SimpleERC20Token.sol"  # this will change in the next PR where the contracts
                                               # will be moved to a different directory.
    success = soda_helper.setup_contract(contract_path, "Token")
    if not success:
        print("Failed to set up the contract")
        return
    # We deploy the contract - this will deploy the contract with 1000000 as the argument to the constructor.
    # Multiple values can be passed as arguments to the constructor as function args.
    # This example uses only one argument, but the function can take multiple arguments like so:
    # receipt = soda_helper.deploy_contract("Token", constructor_args=[1000000, 0xbeef...cafe, 18]) 
    # in this case the constructor of the contract would take 3 arguments.
    total_tokens = 1000000
    receipt = soda_helper.deploy_contract("Token", constructor_args=[total_tokens])
    if receipt is None:
        print("Failed to deploy the contract")
        return
    print(f"Contract deployed at address: {receipt.contractAddress}")
    # We call a view function of the contract - this will call the view function 'balanceOf' with the address 
    # of the account as the argument. The number of arguments can be different for different functions.
    balance_sender_before = soda_helper.call_contract_view("Token", "balanceOf", func_args=[soda_helper.account.address])
    if balance_sender_before is None:
        print("Failed to call the view function")
        return
    print(f"Balance of the account: {balance_sender_before}")
    assert balance_sender_before == total_tokens
    # We call a transaction function of the contract - this will call the transaction function 'transfer' with the address
    # of the account and 100 as the arguments. The number of arguments can be different for different functions.
    amount_to_transfer = 100
    receipt = soda_helper.call_contract_transaction("Token", "transfer", func_args=[RECEIVER_ADDRESS, amount_to_transfer])
    if receipt is None:
        print("Failed to call the transaction function")
        return
    print(f"Transaction successful with hash: {receipt.transactionHash.hex()}")
    # We call the view function 'balanceOf' again with the address
    # of the receiver account as the argument.
    balance_receiver_after = soda_helper.call_contract_view("Token", "balanceOf", func_args=[RECEIVER_ADDRESS])
    if balance_receiver_after is None:
        print("Failed to call the view function")
        return
    print(f"Balance of the receiver account after transfer: {balance_receiver_after}")
    assert balance_receiver_after == amount_to_transfer
    # We call the view function 'balanceOf' again with the address of the account as the argument.
    balance_sender_after = soda_helper.call_contract_view("Token", "balanceOf", func_args=[soda_helper.account.address])
    if balance_sender_after is None:
        print("Failed to call the view function")
        return
    print(f"Balance of the sender account after transfer: {balance_sender_after}")
    assert balance_sender_after == balance_sender_before - amount_to_transfer

def full_example(soda_helper):
    transfer_transaction(soda_helper)
    contract_example(soda_helper)

def main():
    soda_helper = SodaWeb3Helper(PRIVATE_KEY, REMOTE_HTTP_PROVIDER_URL)
    full_example(soda_helper)
    

if __name__ == "__main__":
    main()
