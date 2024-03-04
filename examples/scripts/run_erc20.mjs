import fs from 'fs';
import { block_size, decrypt, prepareIT, hexBase } from '../../tools/js/crypto.js';
import solc from 'solc';
import Web3 from 'web3';

const SOLC_VERSION = '0.8.19';
const FILE_PATH = 'ERC20TokenStandardContract.sol';
const PROVIDER_URL = 'http://localhost:7000';
const INITIAL_BALANCE = 500000000

function checkInstalledSolcVersion(solcVersion) {
    const installedVersion = solc.version();
    console.log('Installed Solc version:', installedVersion);
    if (!installedVersion.includes(solcVersion)) {
        throw new Error(`Solc version ${solcVersion} is not installed. Please install it.`);
    } else {
        console.log(`Solc version ${solcVersion} is already installed.`);
    }
}

function readSolidityCode(filePath) {
    if (!fs.existsSync(filePath)) {
        throw new Error(`The file ${filePath} does not exist`);
    }
    return fs.readFileSync(filePath, 'utf8');
}

function compileSolidity(solcVersion, filePath, solidityCode, mpcInstPath, mpcCorePath) {
    const input = {
        language: 'Solidity',
        sources: {
            'MPCInst.sol': { content: fs.readFileSync(mpcInstPath, 'utf8') },
            'MpcCore.sol': { content: fs.readFileSync(mpcCorePath, 'utf8') },
            [filePath]: { content: solidityCode },
        },
        settings: {
            outputSelection: {
                '*': {
                    '*': ['abi', 'metadata', 'evm.bytecode', 'evm.bytecode.sourceMap'],
                },
            },
        },
    };
    const output = JSON.parse(solc.compile(JSON.stringify(input)));
    return output.contracts[filePath][filePath.split('.')[0]];
}

async function deployContract(web3, account, contractABI, contractBytecode, gas_limit=10000000, gas_price='30'){
    const contract = new web3.eth.Contract(contractABI);
    const deployTx = contract.deploy({
        data: contractBytecode,
        arguments: ["Soda", "SOD", INITIAL_BALANCE]
    });
    const deployOptions = {
        data: deployTx.encodeABI(),
        gas: gas_limit,
        from: account.address,
        gasPrice: web3.utils.toWei(gas_price.toString(), 'gwei') // Convert gas price to wei
    };

    try {
        const signedTx = await web3.eth.accounts.signTransaction(deployOptions, account.privateKey);
        const txHash = await new Promise((resolve, reject) => {
            web3.eth.sendSignedTransaction(signedTx.rawTransaction)
                .once('receipt', receipt => resolve(receipt.transactionHash))
                .once('error', reject);
        });
    
        const receipt = await web3.eth.getTransactionReceipt(txHash);
        console.log('Contract deployed at:', receipt.contractAddress);
    
        // Access the deployed contract instance using new keyword
        const deployedContract = new web3.eth.Contract(contractABI, receipt.contractAddress);
        
        // Access the deployed contract's address
        console.log('Deployed contract address:', deployedContract.options.address);
    
        return deployedContract;
        // return new web3.eth.Contract(contractABI, receipt.contractAddress);
    } catch (error) {
        console.error('Error deploying contract:', error);
        throw error;
    }
    
}

async function executeTransaction(web3, account, func, gas_limit=10000000, gas_price='30') {
    try {
        const nonce = await web3.eth.getTransactionCount(account.address);
        const transaction = await func.send({
            from: account.address,
            chainId: 50505050,
            gas: gas_limit,
            gasPrice: web3.utils.toWei(gas_price, 'gwei'),
            nonce: nonce,
        });

        const txnReceipt = await web3.eth.getTransactionReceipt(transaction.transactionHash);
        console.log(`Transaction successful with hash: ${txnReceipt.transactionHash}`);
        return txnReceipt;
    } catch (error) {
        console.error('Error executing transaction:', error);
        throw error;
    }
}

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

function decryptValue(myCTBalance, userKey) {

    // Convert CT to bytes
    let ctString = myCTBalance.toString(hexBase);
    let ctArray = Buffer.from(ctString, 'hex');
    while (ctArray.length < 32) { // When the first bits are 0, bigint bit size is less than 32 and need to re-add the bits
        ctString = "0" + ctString;
        ctArray = Buffer.from(ctString, 'hex');
    }
    // Split CT into two 128-bit arrays r and cipher
    const cipher = ctArray.subarray(0, block_size);
    const r = ctArray.subarray(block_size);

    // Decrypt the cipher
    const decryptedMessage = decrypt(userKey, r, cipher);

    // console.log the decrypted cipher
    const decryptedBalance = parseInt(decryptedMessage.toString('hex'), block_size);

    return decryptedBalance;
}

async function executeAndCheckBalance(web3, account, func, contract, user_key, expectedBalance){
    await executeTransaction(web3, account, func);
    // Get my encrypted balance, decrypt it and check if it is equal to the expected balance
    const my_CTBalance = await contract.methods.balanceOf().call({'from': account.address});
    const my_balance = decryptValue(my_CTBalance, user_key);
    checkExpectedResult('transfer', expectedBalance, my_balance);
}

async function checkAllowance(account, contract, user_key, expectedAllowance){
    // Get my encrypted allowance, decrypt it and check if it is equal to the expected allowance
    let allowanceCT = await contract.methods.allowance(account.address, account.address).call({'from': account.address})
    let allowance = decryptValue(allowanceCT, user_key)
    checkExpectedResult('allowance', expectedAllowance, allowance)
}

async function main() {
    checkInstalledSolcVersion(SOLC_VERSION);
    const solidityCode = readSolidityCode("../contracts/" + FILE_PATH);
    
    const mpcInstPath = '../../lib/solidity/MPCInst.sol';
    const mpcCorePath = '../../lib/solidity/MpcCore.sol';
    const compiledContract = compileSolidity(SOLC_VERSION, FILE_PATH, solidityCode, mpcInstPath, mpcCorePath);

    const web3 = new Web3(new Web3.providers.HttpProvider(PROVIDER_URL));
    if (!web3.eth.net.isListening()) {
        console.log("Failed to connect to the Ethereum node.");
        return;
    }
    const SIGNING_KEY = process.env.SIGNING_KEY;
    web3.eth.accounts.wallet.add(SIGNING_KEY);
    const account = web3.eth.accounts.wallet[0];

    let contract = web3.eth.Contract 
    contract = await deployContract(web3, account, compiledContract.abi, compiledContract.evm.bytecode.object);
    
    console.log("************* View functions *************");
    const contractName = await contract.methods.name().call({'from': account.address});
    console.log("Function call result name:", contractName);

    const symbol = await contract.methods.symbol().call({'from': account.address});
    console.log("Function call result symbol:", symbol);

    const decimals = await contract.methods.decimals().call({'from': account.address});
    console.log("Function call result decimals:", decimals);

    const totalSupply = await contract.methods.totalSupply().call({'from': account.address});
    console.log("Function call result totalSupply:", totalSupply);

    const user_key_hex = process.env.USER_KEY;
    const user_key = Buffer.from(user_key_hex, 'hex');

    console.log("************* Initial balance = ", INITIAL_BALANCE, " *************");
    let my_CTBalance = await contract.methods.balanceOf().call({'from': account.address});
    let my_balance = decryptValue(my_CTBalance, user_key);
    checkExpectedResult('balanceOf', INITIAL_BALANCE, my_balance);

    // Generate a new account for Alice
    const alice_address = web3.eth.accounts.create();

    const plaintext_integer = 5;


    console.log("************* Transfer clear ", plaintext_integer, " to Alice *************");
    // Transfer 5 SOD to Alice
    let func = contract.methods.transfer(alice_address.address, plaintext_integer, true);
    await executeAndCheckBalance(web3, account, func, contract, user_key, INITIAL_BALANCE - plaintext_integer)

    console.log("************* Transfer clear ", plaintext_integer, " to Alice *************");
    // Transfer 5 SOD to Alice
    func = contract.methods.contractTransferClear(alice_address.address, plaintext_integer);
    await executeAndCheckBalance(web3, account, func, contract, user_key, INITIAL_BALANCE - 2*plaintext_integer)

    console.log("************* Transfer IT ", plaintext_integer, " to Alice *************")
    // In order to generate the input text, we need to use some data of the function. 
    // For example, the address of the user, the address of the contract and also the function signature.
    // In order to get the function signature as simple as possible, we decided to use a dummy function with dummy inputs and use it to generate the signature.
    // After the signature is generated, we call prepare input text function and get the input text to use in the real function.
    const dummyCT = 0;
    const dummySignature = Buffer.alloc(65);
    func = contract.methods.transfer(alice_address.address, dummyCT, dummySignature, false); // Create dummy function to get the signature for prepare input text
    let hashFuncSig = getFunctionSignature(func);
    // After the function signature is obtained, prepare the input test for the function
    let {ctInt, signature} = prepareIT(plaintext_integer, user_key, account.address, contract.options.address, hashFuncSig, Buffer.from(SIGNING_KEY.slice(2), 'hex'));
    // Create the real function using the prepared IT
    func = contract.methods.transfer(alice_address.address, ctInt, signature, false);
    // Transfer 5 SOD to Alice
    await executeAndCheckBalance(web3, account, func, contract, user_key, INITIAL_BALANCE - 3*plaintext_integer)

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice without allowance *************")
    // Trying to transfer 5 SOD to Alice. There is no allowance, transfer should fail
    func = contract.methods.transferFrom(account.address, alice_address.address, plaintext_integer, true)
    // There is no allowance, balance should remain the same
    await executeAndCheckBalance(web3, account, func, contract, user_key, INITIAL_BALANCE - 3*plaintext_integer)

    console.log("************* Approve ", plaintext_integer*10, " to my address *************")
    // Set allowance for this account
    func = contract.methods.approveClear(account.address, plaintext_integer*10)
    await executeTransaction(web3, account, func)
    // Get my allowance to check that the allowance is correct
    checkAllowance(account, contract, user_key, plaintext_integer*10)

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    // Transfer 5 SOD to Alice
    func = contract.methods.transferFrom(account.address, alice_address.address, plaintext_integer, true)
    await executeAndCheckBalance(web3, account, func, contract, user_key, INITIAL_BALANCE - 4*plaintext_integer)

    console.log("************* Transfer clear ", plaintext_integer, " from my account to Alice *************")
    // Transfer 5 SOD to Alice
    func = contract.methods.contractTransferFromClear(account.address, alice_address.address, plaintext_integer)
    await executeAndCheckBalance(web3, account, func, contract, user_key, INITIAL_BALANCE - 5*plaintext_integer)

    console.log("************* Transfer IT ", plaintext_integer, " from my account to Alice *************");
    // Transfer 5 SOD to Alice
    func = contract.methods.transferFrom(account.address, alice_address.address, dummyCT, dummySignature, false);
    hashFuncSig = getFunctionSignature(func);
    ({ctInt, signature} = prepareIT(plaintext_integer, user_key, account.address, contract.options.address, hashFuncSig, Buffer.from(SIGNING_KEY.slice(2), 'hex')));
    // Create the real function using the prepared IT output
    func = contract.methods.transferFrom(account.address, alice_address.address, ctInt, signature, false);
    await executeAndCheckBalance(web3, account, func, contract, user_key, INITIAL_BALANCE - 6*plaintext_integer);
    
    console.log("************* Check my allowance *************")
    // Check the remainning allowance
    checkAllowance(account, contract, user_key, plaintext_integer*7)

    console.log("************* Approve IT 50 to my address *************")
    // Approve 50 SOD to this account
    func = contract.methods.approve(account.address, dummyCT, dummySignature); // Dummy function to get the signature
    hashFuncSig = getFunctionSignature(func);
    ({ctInt, signature} = prepareIT(50, user_key, account.address, contract.options.address, hashFuncSig, Buffer.from(SIGNING_KEY.slice(2), 'hex')));
    func = contract.methods.approve(account.address, ctInt, signature);
    await executeTransaction(web3, account, func);

    console.log("************* Check my allowance *************")
    // Check that the allowance has changed to 50 SOD
    checkAllowance(account, contract, user_key, 50);
}

main();
