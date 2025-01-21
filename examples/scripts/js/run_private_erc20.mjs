import { BLOCK_SIZE, decrypt, prepareIT, HEX_BASE } from 'soda-sdk';
import {
    SodaWeb3Helper,
    LOCAL_PROVIDER_URL,
    REMOTE_HTTP_PROVIDER_URL
} from '../../../lib/js/sodaWeb3Helper.mjs';
import yargs from "yargs";
import {hideBin} from "yargs/helpers";

const FILE_NAME = 'PrivateERC20Contract.sol';
const FILE_PATH = 'examples/contracts/';
const INITIAL_BALANCE = 500000000
let NONCE = 0;

function checkExpectedResult(name, expectedResult, result) {
    if (result === expectedResult) {
        console.log(`Test ${name} succeeded: ${result}`);
    } else {
        throw new Error(`Test ${name} failed. Expected: ${expectedResult}, Actual: ${result}`);
    }
}

function getFunctionSignature(func) {
    const encodedABI = func.encodeABI();
    return Buffer.from(encodedABI.substr(2, 8), 'hex');
}

function uint8ArrayToBigInt(uint8Array) {
    let value = BigInt(0);
    for (let i = 0; i < uint8Array.length; i++) {
        value = (value << 8n) | BigInt(uint8Array[i]);
    }
    return value;
}

function decryptValue(myCTBalance, userKey) {

    // Convert CT to bytes
    let ctString = myCTBalance.toString(HEX_BASE);
    let ctArray = Buffer.from(ctString, 'hex');
    while (ctArray.length < 32) { // When the first bits are 0, bigint bit size is less than 32 and need to re-add the bits
        ctString = "0" + ctString;
        ctArray = Buffer.from(ctString, 'hex');
    }
    // Split CT into two 128-bit arrays r and cipher
    const cipher = ctArray.subarray(0, BLOCK_SIZE);
    const r = ctArray.subarray(BLOCK_SIZE);

    // Decrypt the cipher
    const decryptedMessage = decrypt(userKey, r, cipher);
    return Number(uint8ArrayToBigInt(decryptedMessage));
}

async function getEncryptedBalance(sodaHelper, contract){
    let func = contract.methods.balanceOf();
    const receipt = await sodaHelper.callContractFunctionTransaction(func);

    // Processing the receipt to extract Balance events
    const balanceEvents = await contract.getPastEvents('Balance', {
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber
    });

    // Filter events for the specific address
    const targetEvent = balanceEvents.find(event => 
        event.returnValues._owner.toLowerCase() === sodaHelper.getAccount().address.toLowerCase()
    );

    if (targetEvent) {
        return targetEvent.returnValues._balance;
    } else {
        console.log("Failed to find balance of the account address in the transaction receipt.");
        return null;
    }
}

async function execute_transaction(sodaHelper, func){
    let estimatedGas = await func.estimateGas({ from: sodaHelper.getAccount().address });
    console.log(`Estimated gas: ${estimatedGas}`);
    
    let hash = await sodaHelper.callContractFunctionTransactionAsync(func, NONCE);
    NONCE += BigInt(1);
    return hash
}

async function checkBalance(sodaHelper, contract, user_key, expectedBalance){
    // Get my encrypted balance, decrypt it and check if it is equal to the expected balance
    const my_CTBalance = await getEncryptedBalance(sodaHelper, contract)
    const my_balance = decryptValue(my_CTBalance, user_key);
    checkExpectedResult('balanceOf', expectedBalance, my_balance);
}

async function checkAllowance(sodaHelper, account, contract, user_key, expectedAllowance){
    // Get my encrypted allowance, decrypt it and check if it is equal to the expected allowance
    let func = await contract.methods.allowance(account.address, account.address);
    const receipt = await sodaHelper.callContractFunctionTransaction(func);

    // Processing the receipt to extract Balance events
    const allowanceEvents = await contract.getPastEvents('Allowance', {
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber
    });

    // Filter events for the specific address
    const targetEvent = allowanceEvents.find(event => 
        event.returnValues._owner.toLowerCase() === sodaHelper.getAccount().address.toLowerCase()
    );

    let allowanceCT = null;
    if (targetEvent) {
        allowanceCT = targetEvent.returnValues._allowance;
    } else {
        console.log("Failed to find the allowance of the account address in the transaction receipt.");
    }

    let allowance = decryptValue(allowanceCT, user_key)
    checkExpectedResult('allowance', expectedAllowance, allowance)
}

async function main() {
    const argv = yargs(hideBin(process.argv))
      .usage('Usage: node $0 <provider_url> [options]')
      .demandCommand(1, 'You must provide the provider_url as a positional argument.')
      .option('use_eip191_signature', {
          alias: 'eip191',
          type: 'boolean',
          default: false,
          describe: 'To use EIP191 signature',
      })
      .help('h')
      .alias('h', 'help')
      .parseSync();

    let providerURL = argv._[0];

    switch (argv._[0]) {
        case 'Local':
            providerURL = LOCAL_PROVIDER_URL;
            break;
        case 'Remote':
            providerURL = REMOTE_HTTP_PROVIDER_URL;
            break;
    }

    console.log("Use EIP191 Signature:", argv["use_eip191_signature"]);
    console.log("Provider URL:", providerURL);
    const useEIP191 = argv["use_eip191_signature"]

    // Get the private key from the environment variable
    const SIGNING_KEY = process.env.SIGNING_KEY;
    // Create helper function using the private key
    const sodaHelper = new SodaWeb3Helper(SIGNING_KEY, providerURL);

    // compile the onboard solidity contract
    const success = sodaHelper.setupContract(FILE_PATH, FILE_NAME, "private_erc20");
    if (!success){
        console.log("Failed to set up the contract")
        return
    }

    // Deploy the contract
    let receipt = await sodaHelper.deployContract("private_erc20", ["Soda", "SOD", INITIAL_BALANCE]);
    if (!receipt){
        console.log("Failed to deploy the contract")
        return
    }

    NONCE = await sodaHelper.getCurrentNonce();

    console.log("************* View functions *************");
    const contractName = await sodaHelper.callContractView("private_erc20", "name")
    console.log("Function call result name:", contractName);

    const symbol = await sodaHelper.callContractView("private_erc20", "symbol")
    console.log("Function call result symbol:", symbol);

    const decimals = await sodaHelper.callContractView("private_erc20", "decimals")
    console.log("Function call result decimals:", decimals);

    const totalSupply = await sodaHelper.callContractView("private_erc20", "totalSupply")
    console.log("Function call result totalSupply:", totalSupply);

    const user_key_hex = process.env.USER_KEY;
    const user_key = Buffer.from(user_key_hex, 'hex');

    // Generate a new account for Alice
    const alice_address = sodaHelper.generateRandomAccount();
    
    const contract = sodaHelper.getContract("private_erc20")
    const account = sodaHelper.getAccount();
    
    const plaintext_integer = 5;


    console.log("************* Transfer clear ", plaintext_integer, " to Alice *************");
    // Transfer 5 SOD to Alice
    let func = contract.methods.transfer(alice_address.address, plaintext_integer, true);
    await execute_transaction(sodaHelper, func);

    console.log("************* Transfer clear ", plaintext_integer, " to Alice *************");
    // Transfer 5 SOD to Alice
    func = contract.methods.contractTransferClear(alice_address.address, plaintext_integer);
    await execute_transaction(sodaHelper, func);

    console.log("************* Transfer IT ", plaintext_integer, " to Alice *************")
    // In order to generate the input text, we need to use some data of the function. 
    // For example, the address of the user, the address of the contract and also the function signature.
    // To simplify the process of obtaining the function signature, we use a dummy function with placeholder inputs.
    // After the signature is generated, we call prepare input text function and get the input text to use in the real function.
    const dummyCT = 0;
    const dummySignature = Buffer.alloc(65);
    func = contract.methods.transfer(alice_address.address, dummyCT, dummySignature, false); // Create dummy function to get the signature for prepare input text
    let hashFuncSig = getFunctionSignature(func);
    // After the function signature is obtained, prepare the input test for the function
    let {ctInt, signature} = prepareIT(
      plaintext_integer,
      user_key,
      Buffer.from(account.address.toString().slice(2), 'hex'),
      Buffer.from(contract.options.address.toString().slice(2), 'hex'),
      hashFuncSig,
      Buffer.from(SIGNING_KEY.slice(2), 'hex'),
      useEIP191
    );
    // Create the real function using the prepared IT
    func = contract.methods.transfer(alice_address.address, ctInt, signature, false);
    // Transfer 5 SOD to Alice
    await execute_transaction(sodaHelper, func, contract)

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice without allowance *************")
    // Trying to transfer 5 SOD to Alice. There is no allowance, transfer should fail
    func = contract.methods.transferFrom(account.address, alice_address.address, plaintext_integer, true);
    // There is no allowance, balance should remain the same
    await execute_transaction(sodaHelper, func);

    console.log("************* Approve ", plaintext_integer*10, " to my address *************")
    // Set allowance for this account
    func = contract.methods.approveClear(account.address, plaintext_integer*10);
    await sodaHelper.callContractFunctionTransactionAsync(func, NONCE);
    NONCE += BigInt(1);

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    // Transfer 5 SOD to Alice
    func = contract.methods.transferFrom(account.address, alice_address.address, plaintext_integer, true);
    await execute_transaction(sodaHelper, func, contract);

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice *************");
    // Transfer 5 SOD to Alice
    func = contract.methods.contractTransferFromClear(account.address, alice_address.address, plaintext_integer);
    await execute_transaction(sodaHelper, func, contract);

    console.log("************* Transfer IT ", plaintext_integer, " from my account to Alice *************");
    // Transfer 5 SOD to Alice
    func = contract.methods.transferFrom(account.address, alice_address.address, dummyCT, dummySignature, false);
    hashFuncSig = getFunctionSignature(func);
    ({ctInt, signature} = prepareIT(
      plaintext_integer,
      user_key,
      Buffer.from(account.address.toString().slice(2), 'hex'),
      Buffer.from(contract.options.address.toString().slice(2), 'hex'),
      hashFuncSig,
      Buffer.from(SIGNING_KEY.slice(2), 'hex'),
      useEIP191)
    );
    // Create the real function using the prepared IT output
    func = contract.methods.transferFrom(account.address, alice_address.address, ctInt, signature, false);
    let hash = await execute_transaction(sodaHelper, func, contract)
    await sodaHelper.waitForTransactionReceipt(hash)

    console.log("************* Check my balance *************")
    await checkBalance(sodaHelper, contract, user_key, INITIAL_BALANCE - 6*plaintext_integer);
    
    console.log("************* Check my allowance *************")
    // Check the remainning allowance
    await checkAllowance(sodaHelper, account, contract, user_key, plaintext_integer*7);
}

main()

