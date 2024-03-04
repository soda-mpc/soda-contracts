import fs from 'fs';
import { generateRSAKeyPair, decryptRSA, sign } from '../../tools/js/crypto.js';
import solc from 'solc';
import Web3 from 'web3';

const SOLC_VERSION = '0.8.19';
const FILE_PATH = 'GetUserKeyContract.sol';
const PROVIDER_URL = 'http://localhost:7000';

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
        data: contractBytecode
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
    
        return new web3.eth.Contract(contractABI, receipt.contractAddress);
    } catch (error) {
        console.error('Error deploying contract:', error);
        throw error;
    }
    
}

async function executeTransaction(web3, account, contract, func, gas_limit=10000000, gas_price='30') {
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

async function main() {
    checkInstalledSolcVersion(SOLC_VERSION);
    const solidityCode = readSolidityCode("../contracts/" + FILE_PATH);
    
    const mpcInstPath = '../../lib/solidity/MPCInst.sol';
    const mpcCorePath = '../../lib/solidity/MpcCore.sol';
    const compiledContract = compileSolidity(SOLC_VERSION, FILE_PATH, solidityCode, mpcInstPath, mpcCorePath);

    const web3 = new Web3(new Web3.providers.HttpProvider(PROVIDER_URL));
    if (!web3.eth.net.isListening()) {
        console.log("Failed to connect to the node.");
        return;
    }
    const SIGNING_KEY = process.env.SIGNING_KEY;
    web3.eth.accounts.wallet.add(SIGNING_KEY);
    const account = web3.eth.accounts.wallet[0];

    const contract = await deployContract(web3, account, compiledContract.abi, compiledContract.evm.bytecode.object);
    
    const { publicKey, privateKey } = generateRSAKeyPair();
    const signedEK = sign(publicKey, Buffer.from(SIGNING_KEY.slice(2), 'hex'));
    
    const func = contract.methods.getUserKey(publicKey, signedEK);
    await executeTransaction(web3, account, contract, func);
    
    const encryptedKey = await contract.methods.getSavedUserKey().call({ from: account.address });
    const buf = Buffer.from(encryptedKey.substring(2), 'hex');
    const decryptedAESKey = decryptRSA(privateKey, buf);
    console.log("user AES key:", decryptedAESKey.toString('hex'));

    fs.appendFileSync('../../.env', `export USER_KEY='${decryptedAESKey.toString('hex')}'\n`);
}

main();
