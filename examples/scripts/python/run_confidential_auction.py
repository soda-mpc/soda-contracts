import os
from eth_account import Account
from soda_python_sdk import prepare_IT
from lib.python.soda_web3_helper import (SodaWeb3Helper, parse_url_parameter, get_function_signature, decrypt_value_int,
                                         decrypt_value_bool, execute_transaction, extract_event_value, get_user_aes_key)

CONFIDENTIAL_AUCTION_FILE_NAME = 'ConfidentialAuction.sol'
PRIVATE_ERC20_FILE_NAME = 'PrivateERC20Contract.sol'
FILE_PATH = 'examples/contracts/'
INITIAL_BALANCE = 500000000


def get_private_erc20_balance(soda_helper, account, erc20_contract, user_key):
    function = erc20_contract.functions.balanceOf()
    receipt = soda_helper.call_contract_function_transaction("private_erc20", function, account=account)
    if receipt is None:
        print("Failed to call the balanceOf() function")

    def filter_func(event):
        return event['args']['_owner'].lower() == account.address.lower()

    balance_encrypted = extract_event_value(
        erc20_contract,
        receipt,
        filter_func,
        event_name='Balance',
        target_attribute='_balance')
    balance = decrypt_value_int(balance_encrypted, user_key)
    return balance


def get_bid(soda_helper, account, confidential_auction_contract, user_key):
    function = confidential_auction_contract.functions.getBid()
    receipt = soda_helper.call_contract_function_transaction("confidential_auction", function)
    if receipt is None:
        print("Failed to call the getBid() function")

    def filter_func(event):
        return event['args']['_reader'].lower() == account.address.lower()

    bid_encrypted = extract_event_value(
        confidential_auction_contract,
        receipt,
        filter_func,
        event_name='Bid',
        target_attribute='_value')
    bid = decrypt_value_int(bid_encrypted, user_key)
    return bid


def get_is_highest_bidder(soda_helper, account, confidential_auction_contract, user_key):
    function = confidential_auction_contract.functions.doIHaveHighestBid()
    receipt = soda_helper.call_contract_function_transaction("confidential_auction", function)
    if receipt is None:
        print("Failed to call the doIHaveHighestBid() function")

    def filter_func(event):
        return event['args']['_reader'].lower() == account.address.lower()

    value_encrypted = extract_event_value(
        confidential_auction_contract,
        receipt,
        filter_func,
        event_name='IsHighestBidder',
        target_attribute='_value')
    print(f'IsHighestBidder encrypted: {value_encrypted}')

    value = decrypt_value_bool(value_encrypted, user_key)
    return value


def main(provider_url: str):
    # Get the account private key from the environment variable
    private_key = os.environ.get('SIGNING_KEY')
    owner = Account.from_key(private_key)
    print(f'Owner Address: {owner.address}')

    user_key_hex = os.environ.get('USER_KEY')
    user_key = bytes.fromhex(user_key_hex)

    soda_helper = SodaWeb3Helper(private_key, provider_url)

    beneficiary = Account.create()
    # send some native currency to beneficiary to execute the transaction
    soda_helper.transfer_native_currency(beneficiary.address, 0.1, is_async=False, account=owner)

    owner_aes_key = get_user_aes_key(soda_helper, owner)
    beneficiary_aes_key = get_user_aes_key(soda_helper, beneficiary)

    # Compile the contract
    success = soda_helper.setup_contract(FILE_PATH + PRIVATE_ERC20_FILE_NAME,"private_erc20")
    if not success:
        print("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("private_erc20", constructor_args=["Soda", "SOD", INITIAL_BALANCE])
    if receipt is None:
        print("Failed to deploy the contract")

    private_erc20 = soda_helper.get_contract("private_erc20")

    # Compile the contract
    success = soda_helper.setup_contract(
        FILE_PATH + CONFIDENTIAL_AUCTION_FILE_NAME,
        'confidential_auction',
        additional_sources={"PrivateERC20Contract.sol": {"urls": ["examples/contracts/PrivateERC20Contract.sol"]}}
    )
    if not success:
        print('Failed to set up the contract')

    # Deploy the contract
    receipt = soda_helper.deploy_contract('confidential_auction', constructor_args=[
        beneficiary.address,
        private_erc20.address,
        60 * 60 * 24,
        True
    ])
    if receipt is None:
        print('Failed to deploy the contract')

    confidential_auction_contract = soda_helper.get_contract('confidential_auction')
    print(f'Contract Address: {confidential_auction_contract.address}')

    print('************* View functions tests *************')
    bid_counter_res = confidential_auction_contract.functions.bidCounter().call()
    assert bid_counter_res == 0, f'bidCounter {bid_counter_res} does not match expected value 0'

    end_time_res = confidential_auction_contract.functions.endTime().call()
    assert end_time_res != 0, f'endTime {end_time_res} is 0'

    contract_owner_res = confidential_auction_contract.functions.contractOwner().call()
    assert contract_owner_res == owner.address, f'contractOwner {contract_owner_res} does not match owner address'

    beneficiary_res = confidential_auction_contract.functions.beneficiary().call()
    assert beneficiary_res == beneficiary.address, f'beneficiary {beneficiary_res} does not match beneficiary address'
    print("View functions tests passed")

    print('************* Bidding tests *************')
    bid_amount = 100

    print('Bidding with the owner account', bid_amount)
    owner_balance_before = get_private_erc20_balance(soda_helper, owner, private_erc20, user_key)
    print(f'Owner balance before: {owner_balance_before}')

    # approve spending of the bid amount
    function = private_erc20.functions.approveClear(confidential_auction_contract.address, bid_amount)
    execute_transaction(soda_helper, owner, 'private_erc20', function)
    print(f'Approved {bid_amount} to the auction contract')

    # bid
    dummy_ct = 0
    dummy_signature = bytes(65)
    function = confidential_auction_contract.functions.bid(dummy_ct, dummy_signature)
    func_sig = get_function_signature(function.abi)
    bid_ct, signature = prepare_IT(bid_amount, user_key, owner, confidential_auction_contract, func_sig,
                                   bytes.fromhex(private_key[2:]))
    print(f'Bid CT: {bid_ct}')
    function = confidential_auction_contract.functions.bid(bid_ct, signature)
    receipt = soda_helper.call_contract_function_transaction('confidential_auction', function)
    if receipt is None:
        print('Failed to submit the bid')
    print('Bid submitted')

    owner_balance_after = get_private_erc20_balance(soda_helper, owner, private_erc20, user_key)
    assert owner_balance_after == owner_balance_before - bid_amount, \
        f'Owner balance {owner_balance_after} does not match expected value {owner_balance_before - bid_amount}'

    bid = get_bid(soda_helper, owner, confidential_auction_contract, user_key)
    assert bid == bid_amount, f'bid {bid} does not match expected value {bid_amount}'

    new_bid_amount = 200
    print('Increase the bid amount:', new_bid_amount)

    # approve spending of the bid amount
    function = private_erc20.functions.approveClear(confidential_auction_contract.address, new_bid_amount)
    execute_transaction(soda_helper, owner, 'private_erc20', function)
    print(f'Approved {new_bid_amount} to the auction contract')

    # bid
    dummy_ct = 0
    dummy_signature = bytes(65)
    function = confidential_auction_contract.functions.bid(dummy_ct, dummy_signature)
    func_sig = get_function_signature(function.abi)
    bid_ct, signature = prepare_IT(new_bid_amount, user_key, owner, confidential_auction_contract, func_sig,
                                   bytes.fromhex(private_key[2:]))
    print(f'Bid CT: {bid_ct}')
    function = confidential_auction_contract.functions.bid(bid_ct, signature)
    receipt = soda_helper.call_contract_function_transaction('confidential_auction', function)
    if receipt is None:
        print('Failed to submit the bid')
    print('Bid submitted')
    owner_balance_after_2nd_bid = get_private_erc20_balance(soda_helper, owner, private_erc20, user_key)

    print(f'Owner balance after 2nd bid: {owner_balance_after_2nd_bid}')
    assert owner_balance_after_2nd_bid == owner_balance_before - new_bid_amount

    print('************* Closing the auction *************')

    function = confidential_auction_contract.functions.stop()
    receipt = execute_transaction(soda_helper, owner, 'confidential_auction', function)
    if receipt is None:
        print('Failed to close the auction')

    # the highest bidder is known only if the auction is over
    is_highest_bidder = get_is_highest_bidder(soda_helper, owner, confidential_auction_contract, user_key)
    print(f'is_highest_bidder: {is_highest_bidder}')
    assert is_highest_bidder, f'is_highest_bidder {is_highest_bidder} does not match expected value True'

    print('************* Highest bidder claims auctioned item *************')

    function = confidential_auction_contract.functions.claim()
    receipt = execute_transaction(soda_helper, owner, 'confidential_auction', function)
    if receipt is None:
        print("Failed to call the balanceOf() function")

    def filter_func(event):
        return event['args']['who'].lower() == owner.address.lower()

    winner_address = extract_event_value(
        confidential_auction_contract,
        receipt,
        filter_func,
        event_name='Winner',
        target_attribute='who')

    assert winner_address == owner.address, 'Incorrect winner address'
    print(f'Winner address: {winner_address}')

    print('************* Transfer tokens to the beneficiary  *************')
    function = confidential_auction_contract.functions.auctionEnd()
    receipt = execute_transaction(soda_helper, owner, 'confidential_auction', function)
    if receipt is None:
        print("Failed to call the balanceOf() function")

    beneficiary_balance = get_private_erc20_balance(soda_helper, beneficiary, private_erc20, beneficiary_aes_key)
    print(f'Beneficiary balance: {beneficiary_balance}')
    assert beneficiary_balance == new_bid_amount, \
        f'beneficiary_balance {beneficiary_balance} does not match expected value {new_bid_amount}'


if __name__ == "__main__":
    url = parse_url_parameter()
    if url is not None:
        main(url)
