from eth_account import Account

account = Account.create()

print("Account address: ", account.address)

# Write the data to a .env file
with open('.env', 'a') as f:
    f.write(f"export SIGNING_KEY='{account._private_key.hex()}'\n")