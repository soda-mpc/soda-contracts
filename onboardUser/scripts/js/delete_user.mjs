import fs from 'fs';
import { prepareDeleteKeySignature} from '../../../soda-sdk/js/crypto.js';
import {SodaWeb3Helper, parseURLParameter} from '../../../lib/js/sodaWeb3Helper.mjs';

const FILE_NAME = 'GetUserKeyContract.sol';
const FILE_PATH = 'onboardUser/contracts/';

function getFunctionSignature(func) {
    const encodedABI = func.encodeABI();
    return Buffer.from(encodedABI.substr(2, 8), 'hex');
}

function removeUserKeyFromFile(filename) {
    // Read the original file and filter out the line containing "USER_KEY"
    const fileContent = fs.readFileSync(filename, 'utf-8');
    const lines = fileContent.split('\n');
    const tempLines = lines.filter(line => !line.includes("USER_KEY"));
    
    // Write the modified content back to the same file
    fs.writeFileSync(filename, tempLines.join('\n'), 'utf-8');
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

    const account = sodaHelper.getAccount();
    const contract = sodaHelper.getContract("onboard_user");
    
    // There could be a situation where a request to delete a user's key is hidden within a malicious function. 
    // Unknowingly, the user might activate it, inadvertently causing their key to be deleted. 
    // To prevent such an occurrence, it's essential to confirm that the individual requesting the key deletion is indeed the 
    // key's owner and is fully conscious of the deletion process. 
    // This is achieved by requiring the user's signature on both the user's address and the contract's address, as well as 
    // on the function signature. By mandating the user's signature on the contract and function that entails a key deletion call, 
    // it ensures that the user is informed that their key will be deleted, thereby preventing accidental or malicious deletions.
    
    // To simplify the process of obtaining the function signature, we use a dummy function with placeholder inputs.
    // After the signature is generated, we call prepare input text function and get the input text to use in the real function.
    const dummySignature = Buffer.alloc(65);
    let func = contract.methods.deleteUserKey(dummySignature)
    const hashFuncSig = getFunctionSignature(func); // Get the function signature
    // Sign the message
    const signature = prepareDeleteKeySignature(account.address, contract.options.address, hashFuncSig, Buffer.from(SIGNING_KEY.slice(2), 'hex'))
    func = contract.methods.deleteUserKey(signature);
    // Call the deleteUserKey function to delete the encrypted AES key
    receipt = await sodaHelper.callContractTransaction("onboard_user", "deleteUserKey", [signature]);
    if (!receipt){
        throw new Error("Failed to call the transaction function")
    }
    
    removeUserKeyFromFile('.env')
    
}

main()
  .catch(error => {
    console.error(error)
  });

