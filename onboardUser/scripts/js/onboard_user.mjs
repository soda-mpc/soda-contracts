import fs from 'fs';
import { generateRSAKeyPair, decryptRSA, sign } from '../../../soda-sdk/js/crypto.js';
import {SodaWeb3Helper, REMOTE_HTTP_PROVIDER_URL} from '../../../lib/js/sodaWeb3Helper.mjs';

const FILE_NAME = 'GetUserKeyContract.sol';
const FILE_PATH = 'onboardUser/contracts/';

async function main() {
    // Get the private key from the environment variable
    const SIGNING_KEY = process.env.SIGNING_KEY;
    // Create helper function using the private key
    const sodaHelper = new SodaWeb3Helper(SIGNING_KEY, REMOTE_HTTP_PROVIDER_URL);

    // compile the onboard solidity contract
    const success = sodaHelper.setupContract(FILE_PATH, FILE_NAME, "onboard_user");
    if (!success){
        console.log("Failed to set up the contract")
        return
    }

    // Deploy the contract
    let receipt = await sodaHelper.deployContract("onboard_user");
    if (!receipt){
        console.log("Failed to deploy the contract")
        return
    }
    
    // Generate RSA keys and sign the public key
    const { publicKey, privateKey } = generateRSAKeyPair();
    const signedEK = sign(publicKey, Buffer.from(SIGNING_KEY.slice(2), 'hex'));
    
    // Call the getUserKey function to get the encrypted AES key
    await sodaHelper.callContractTransaction("onboard_user", "getUserKey", [publicKey, signedEK]);
    const encryptedKey = await sodaHelper.callContractView("onboard_user", "getSavedUserKey")

    // Decrypt the AES key using the RSA private key
    const buf = Buffer.from(encryptedKey.substring(2), 'hex');
    const decryptedAESKey = decryptRSA(privateKey, buf);

    fs.appendFileSync('.env', `export USER_KEY='${decryptedAESKey.toString('hex')}'\n`);
}

main();
