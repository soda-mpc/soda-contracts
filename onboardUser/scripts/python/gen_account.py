from eth_account import Account

account = Account.create()

print("Account address: ", account.address)

# Clear the .env file and write the new signing key to the .env file
with open('.env', 'w') as f:
    f.write(f"export SIGNING_KEY='{account._private_key.hex()}'\n")