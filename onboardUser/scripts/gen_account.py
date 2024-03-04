import os
import sys
from eth_account import Account
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), '../../tools/python')))
from crypto import generate_ECDSA_private_key


private_key = generate_ECDSA_private_key().hex()
private_key = "0x" + private_key
print(f'Private key: {private_key}')

account = Account.from_key(private_key)

print("Account address: ", account.address)

# Write the data to a .env file
with open('../../.env', 'a') as f:
    f.write(f"export SIGNING_KEY='{private_key}'\n")