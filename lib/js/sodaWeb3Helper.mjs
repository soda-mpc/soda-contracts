import Web3 from 'web3';
import solc from 'solc';
import fs from 'fs';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

export const LOCAL_PROVIDER_URL = 'http://localhost:7001'
export const REMOTE_HTTP_PROVIDER_URL = 'http://testnet.node.sodalabs.net:7000'
export const DEFAULT_GAS_PRICE = '30';
export const DEFAULT_GAS_LIMIT = '10000000';
const DEFAULT_CHAIN_ID = 50505050;
const SOLC_VERSION = '0.8.19';

export function parseURLParameter(){
    // Set up yargs to parse the command line arguments
    const argv = yargs(hideBin(process.argv))
    .usage('Usage: node $0 <provider_url>')
    .command('$0 <provider_url>', 'Get URL', (yargs) => {
        yargs.positional('provider_url', {
        describe: 'The node url',
        type: 'string',
        })
    })
    .help()
    .alias('help', 'h')
    .parse();

    // Logic to determine which URL to use based on the argument
    if (argv.provider_url === "Local") {
        return LOCAL_PROVIDER_URL;
    } else if (argv.provider_url === "Remote") {
        return REMOTE_HTTP_PROVIDER_URL;
    } else {
        console.log("Invalid provider url");
        return null;
    }
}

export class SodaWeb3Helper {
    constructor(privateKey, httpProviderUrl) {
        this.privateKey = privateKey;

        this.web3 = new Web3(httpProviderUrl);
        if (!this.web3.eth.net.isListening()) {
            console.log("Failed to connect to the node.");
            return;
        }
        console.log(`Connected to the node at ${httpProviderUrl}`);

        this.web3.eth.accounts.wallet.add(privateKey);
        this.account = this.web3.eth.accounts.wallet[0];
        console.log(`Account address is ${this.account.address}`);

        this.contracts = {};
        console.log('SodaWeb3Helper initialized');
    }

    async setupContract(contractPath, contractName, contractId, overwrite = false) {
        if (contractId in this.contracts && !overwrite) {
            console.log(`Contract with id ${contractId} already exists. Use the 'overwrite' parameter to overwrite it.`);
            return false;
        }
    
        try {
            const compiledContract = this.compileContract(contractPath, contractName);
            const bytecode = compiledContract.evm.bytecode.object;
            const contractAbi = compiledContract.abi;
            this.contracts[contractId] = new this.web3.eth.Contract(contractAbi, null, { data: bytecode });
            return true;
        } catch (error) {
            console.error(`Failed to compile the contract: ${error}`);
            return false;
        }
    }

    getContract(contractId) {
        if (!(contractId in this.contracts)) {
            console.log(`Contract with id ${contractId} does not exist. Use the 'setup_contract' method to set it up.`);
            return null;
        }
        return this.contracts[contractId];
    }

    getAccount(){
        return this.account;
    }
    

    generateRandomAccount(){
        return this.web3.eth.accounts.create();
    }

    compileContract(filePath, fileName, MpcInterfacePath = "lib/solidity/MpcInterface.sol", mpcCorePath = "lib/solidity/MpcCore.sol") {
        this.checkInstalledSolcVersion(SOLC_VERSION);
        const solidityCode = this.readSolidityCode(filePath + fileName);

        console.log(`Compiling ${filePath + fileName}...`);
    
        const input = {
            language: 'Solidity',
            sources: {
                'MpcInterface.sol': { content: fs.readFileSync(MpcInterfacePath, 'utf8') },
                'MpcCore.sol': { content: fs.readFileSync(mpcCorePath, 'utf8') },
                [fileName]: { content: solidityCode }
            },
            settings: {
                outputSelection: {
                    '*': {
                        '*': ['abi', 'metadata', 'evm.bytecode', 'evm.bytecode.sourceMap']
                    }
                }
            }
        };

        const compiledSol = JSON.parse(solc.compile(JSON.stringify(input)));
    
        if (!compiledSol.contracts || !compiledSol.contracts[fileName] || !compiledSol.contracts[fileName][fileName.split('.')[0]]) {
            throw new Error(`Compilation failed for contract ${fileName.split('.')[0]}`);
        }

        return compiledSol.contracts[fileName][fileName.split('.')[0]];
    }

    async deployContract(contractId, constructorArgs = [], gasLimit = DEFAULT_GAS_LIMIT, gasPrice = DEFAULT_GAS_PRICE, chainId = DEFAULT_CHAIN_ID) {
        const contract = this.contracts[contractId];
        const funcToCall = contract.deploy({
            data: contract.options.data,
            arguments: constructorArgs
        });
        const nonce = await this.web3.eth.getTransactionCount(this.account.address);
        const constructTxn = {
            from: this.account.address,
            data: funcToCall.encodeABI(),
            chainId: chainId,
            nonce: nonce,
            gas: gasLimit,
            gasPrice: this.web3.utils.toWei(gasPrice.toString(), 'gwei')
        };
        const receipt = await this.signAndSendTransaction(constructTxn);
        
        if (receipt) {
            console.log(`Contract deployed at: ${receipt.contractAddress}`);
            this.contracts[contractId].options.address = receipt.contractAddress;
        }
    
        return receipt;
    }

    // Function to get the current nonce for a given account
    async getCurrentNonce(account=this.account.address) {  
        try {
            return await this.web3.eth.getTransactionCount(account);
        } catch (error) {
            console.error('Error fetching nonce:', error);
            throw error;
        }
    }

    async callContractView(contractId, funcName, funcArgs = []) {
        if (!(contractId in this.contracts)) {
            console.log(`Contract with id ${contractId} does not exist. Use the 'setupContract' method to set it up.`);
            return null;
        }
    
        const contract = this.contracts[contractId];
        const func = contract.methods[funcName];

        try {
            const result = await func(...funcArgs).call({ from: this.account.address });
            return result;
        } catch (error) {
            console.error(`Failed to call function ${funcName}: ${error}`);
            return null;
        }
    }

    async estimateGas(contractId, funcName, funcArgs = []) {
        if (!(contractId in this.contracts)) {
            console.log(`Contract with id ${contractId} does not exist. Use the 'setupContract' method to set it up.`);
            return null;
        }
    
        const contract = this.contracts[contractId];
        const funcToCall = contract.methods[funcName](...funcArgs);
        return funcToCall.estimateGas({ from: this.account.address });
    }

    async callContractTransaction(contractId, funcName, funcArgs = [], gasLimit = DEFAULT_GAS_LIMIT, gasPrice = DEFAULT_GAS_PRICE, chainId = DEFAULT_CHAIN_ID) {
        if (!(contractId in this.contracts)) {
            console.log(`Contract with id ${contractId} does not exist. Use the 'setupContract' method to set it up.`);
            return null;
        }
    
        const contract = this.contracts[contractId];
        const funcToCall = contract.methods[funcName](...funcArgs);
        const receipt = await this.callContractFunctionTransaction(funcToCall, gasLimit, gasPrice, chainId);
        return receipt;
    }

    async callContractFunctionTransaction(func, gasLimit = DEFAULT_GAS_LIMIT, gasPrice = DEFAULT_GAS_PRICE, chainId = DEFAULT_CHAIN_ID) {
        const nonce = await this.web3.eth.getTransactionCount(this.account.address);
        const transaction = {
            from: this.account.address,
            chainId: chainId,
            nonce: nonce,
            gas: gasLimit,
            gasPrice: this.web3.utils.toWei(gasPrice.toString(), 'gwei')
        };
        const receipt = await this.sendTransaction(func, transaction);
        return receipt;
    }

    /**
     * This asynchronous function calls a contract function as a transaction without wait for it to be mined.
     *
     * @param {Function} func - The contract function to call.
     * @param {Object} contract - The contract instance.
     * @param {Number} gasLimit - The maximum gas that can be used for transaction, defaults to DEFAULT_GAS_LIMIT.
     * @param {Number} gasPrice - The price of gas in wei for this transaction, defaults to DEFAULT_GAS_PRICE.
     * @param {Number} chainId - The id of the Ethereum chain, defaults to DEFAULT_CHAIN_ID.
     *
     * @returns {Promise} - A promise that resolves to the result of the sendTransaction function.
     */
    async callContractFunctionTransactionAsync(func, nonce, gasLimit = DEFAULT_GAS_LIMIT, gasPrice = DEFAULT_GAS_PRICE, chainId = DEFAULT_CHAIN_ID) {
        const transaction = {
            from: this.account.address,
            chainId: chainId,
            nonce: nonce,
            gas: gasLimit,
            gasPrice: this.web3.utils.toWei(gasPrice.toString(), 'gwei')
        };

        return this.sendTransaction(func, transaction, true);
    }

    async sendTransaction(funcToCall, transaction, isAsync = false) {
        try {
            if (isAsync) {
                // If async, return the transaction hash immediately after sending
                return new Promise((resolve, reject) => {
                    funcToCall.send(transaction)
                        .on('transactionHash', hash => {
                            resolve(hash);  // Resolve the promise with the hash
                        })
                        .on('error', error => {
                            console.error('Error send transaction:', error);
                            reject(error);  // Reject the promise on error
                        });
                });
            } else {
                // If not async, wait for the receipt
                const tx = await funcToCall.send(transaction);
                const receipt = await this.web3.eth.getTransactionReceipt(tx.transactionHash);
                return receipt;
            }
    
        } catch (error) {
            console.error('Error send transaction:', error);
            throw error;
        }
    }   

    async signAndSendTransaction(transaction) {
        try {
            const signedTx = await this.web3.eth.accounts.signTransaction(transaction, this.account.privateKey);
            const tx = await this.web3.eth.sendSignedTransaction(signedTx.rawTransaction);
            const receipt = await this.web3.eth.getTransactionReceipt(tx.transactionHash);
            return receipt;
    
        } catch (error) {
            console.error('Error sign and send transaction:', error);
            throw error;
        }
    }  

    async waitForTransactionReceipt(txHash) {
        
        let txReceipt = null;
        // Keep trying until we get the receipt
        while (txReceipt === null) {
            try {
                txReceipt = await this.web3.eth.getTransactionReceipt(txHash);
                if (txReceipt !== null) {
                    return txReceipt;
                }
            } catch (error) {
                if (error.message.includes('not found')) {
                    continue;
                } else {
                    console.error('Unexpected error:', error);
                    break;
                }
            }
            // Wait for 1 second before trying again
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }

    checkInstalledSolcVersion(solcVersion) {
        const installedVersion = solc.version();
        if (!installedVersion.includes(solcVersion)) {
            throw new Error(`Solc version ${solcVersion} is not installed. Please install it.`);
        } 
    }
    
    readSolidityCode(filePath) {
        if (!fs.existsSync(filePath)) {
            throw new Error(`The file ${filePath} does not exist`);
        }
        return fs.readFileSync(filePath, 'utf8');
    }
    
}

