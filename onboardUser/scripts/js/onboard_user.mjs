import fs from 'fs';
import { generateRSAKeyPair, recoverUserKey, sign } from '../../../soda-sdk/js/crypto.js';
import {SodaWeb3Helper, parseURLParameter} from '../../../lib/js/sodaWeb3Helper.mjs';

const FILE_NAME = 'GetUserKeyContract.sol';
const FILE_PATH = 'onboardUser/contracts/';

function removeUserKeyFromFile(filename) {
    // Read the original file and filter out the line containing "USER_KEY"
    const fileContent = fs.readFileSync(filename, 'utf-8');
    const lines = fileContent.split('\n');
    const tempLines = lines.filter(line => !line.includes("USER_KEY"));
    
    // Write the modified content back to the same file
    fs.writeFileSync(filename, tempLines.join('\n'), 'utf-8');
}

async function getUserKeyShares(account, contract, receipt) {
    // Processing the receipt to extract Balance events
    const userKeyEvents = await contract.getPastEvents('UserKey', {
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber
    });

    // Filter events for the specific address
    const targetEvent = userKeyEvents.find(event => 
        event.returnValues._owner.toLowerCase() === account.address.toLowerCase()
    );

    let keyShare0 = null;
    let keyShare1 = null;
    if (targetEvent) {
        keyShare0 = targetEvent.returnValues._keyShare0;
        keyShare1 = targetEvent.returnValues._keyShare1;
    } else {
        throw new Error("Failed to find the key shares of the account address in the transaction receipt.");
    }
    return [keyShare0, keyShare1];
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
        throw new Error("Failed to set up the contract")
    }

    // Deploy the contract
    let receipt = await sodaHelper.deployContract("onboard_user");
    if (!receipt){
        throw new Error("Failed to deploy the contract")
    }
    
    // Generate RSA keys and sign the public key
    const { publicKey, privateKey } = generateRSAKeyPair();
    const signedEK = sign(publicKey, Buffer.from(SIGNING_KEY.slice(2), 'hex'));
    
    // Call the getUserKey function to get the encrypted AES key
    receipt = await sodaHelper.callContractTransaction("onboard_user", "getUserKey", [publicKey, signedEK]);
    if (!receipt){
        throw new Error("Failed to call the transaction function")
    }
    let response = await getUserKeyShares(sodaHelper.getAccount(), sodaHelper.getContract("onboard_user"), receipt);
    const encryptedKey0 = response[0];
    const encryptedKey1 = response[1];
    
    // Decrypt the AES key using the RSA private key
    const share0Buf = Buffer.from(encryptedKey0.substring(2), 'hex');
    const share1Buf = Buffer.from(encryptedKey1.substring(2), 'hex');
    const decryptedAESKey = recoverUserKey(privateKey, share0Buf, share1Buf);

    removeUserKeyFromFile('.env'); // Remove the old USER_KEY from the .env file
    // Write the new AES key to the .env file
    fs.appendFileSync('.env', `export USER_KEY='${decryptedAESKey.toString('hex')}'\n`);
    
}

main()
  .catch(error => {
    console.error(error)
  });
