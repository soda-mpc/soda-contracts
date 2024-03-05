import os
from tools.python.crypto import generate_rsa_keypair, decrypt_rsa, sign
from lib.python.soda_web3_helper import SodaWeb3Helper, LOCAL_PROVIDER_URL

FILE_PATH = 'GetUserKeyContract.sol'

def main():

    signing_key = os.environ.get('SIGNING_KEY')
    print(f'Signing key is {signing_key}')

    soda_helper = SodaWeb3Helper(signing_key, LOCAL_PROVIDER_URL)

    # Compile the contract
    success = soda_helper.setup_contract("onboardUser/contracts/" + FILE_PATH, "onboard_user")
    if not success:
        print("Failed to set up the contract")

    # Deploy the contract
    receipt = soda_helper.deploy_contract("onboard_user", constructor_args=[])
    if receipt is None:
        print("Failed to deploy the contract")

    contract = soda_helper.get_contract("onboard_user")
    
    # Generate new RSA key pair
    private_key, public_key = generate_rsa_keypair()
    # Sign the public key
    signedEK = sign(public_key, bytes.fromhex(signing_key[2:]))

    # Call the getUserKey function to get the encrypted AES key
    receipt = soda_helper.call_contract_transaction("onboard_user", "getUserKey", func_args=[public_key, signedEK])
    if receipt is None:
        print("Failed to call the transaction function")
        return
    encryptedKey = contract.functions.getSavedUserKey().call()
    
    # Decrypt the aes key using the RSA private key
    decrypted_aes_key = decrypt_rsa(private_key, encryptedKey)
    # Print the aes key
    print("user AES key:", decrypted_aes_key.hex())

    # Write the data to a .env file
    with open('.env', 'a') as f:
        f.write(f"export USER_KEY='{decrypted_aes_key.hex()}'\n")


if __name__ == "__main__":
    main()
