import fs from 'fs';
import { generateRSAKeyPair, recoverUserKey, sign } from '../../../soda-sdk/js/crypto.js';
import {SodaWeb3Helper, parseURLParameter} from '../../../lib/js/sodaWeb3Helper.mjs';

const FILE_NAME = 'GetUserKeyContract.sol';
const FILE_PATH = 'onboardUser/contracts/';

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
    const url = parseURLParameter();
    if (url === null) {
        return
    }
    
    // Get the private key from the environment variable
    const SIGNING_KEY = process.env.SIGNING_KEY;
    // Create helper function using the private key
    const sodaHelper = new SodaWeb3Helper(SIGNING_KEY, url);

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
    receipt = await sodaHelper.callContractTransaction("onboard_user", "getUserKey", [publicKey, signedEK]);
    if (!receipt){
        console.log("Failed to call the transaction function")
        return
    }
    await sleep(30000); // Wait 30 seconds for the black block 
    let response = await sodaHelper.callContractView("onboard_user", "getSavedUserKey")
    const encryptedKey0 = response[0];
    const encryptedKey1 = response[1];
    
    // Decrypt the AES key using the RSA private key
    const share0Buf = Buffer.from(encryptedKey0.substring(2), 'hex');
    const share1Buf = Buffer.from(encryptedKey1.substring(2), 'hex');
    const decryptedAESKey = recoverUserKey(privateKey, share0Buf, share1Buf);

    fs.appendFileSync('.env', `export USER_KEY='${decryptedAESKey.toString('hex')}'\n`);
    
}

main()
