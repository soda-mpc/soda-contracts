import {SodaWeb3Helper, LOCAL_PROVIDER_URL} from './sodaWeb3Helper.mjs';

const PRIVATE_KEY = "0x2e0834786285daccd064ca17f1654f67b4aef298acbb82cef9ec422fb4975622"
const RECEIVER_ADDRESS = "0xc41Ba88D12f4E1869E287a909aD3D535Ba1FDf80"

export async function main() {
    console.log("Hello, World!");
    console.log("PRIVATE_KEY = ", PRIVATE_KEY);
    console.log("LOCAL_PROVIDER_URL = ", LOCAL_PROVIDER_URL);
    
    const sodaHelper = new SodaWeb3Helper(PRIVATE_KEY, LOCAL_PROVIDER_URL);
    const success = sodaHelper.setupContract("lib/js/", "SimpleERC20Token.sol", 'Token');
    if (!success){
        console.log("Failed to set up the contract")
        return
    }

    const total_tokens = 1000000
    let receipt = await sodaHelper.deployContract("Token", [total_tokens]);
    if (!receipt){
        console.log("Failed to deploy the contract")
        return
    }
    console.log("Contract deployed at address:", receipt.contractAddress);

    const balance_sender_before = await sodaHelper.callContractView("Token", "balanceOf", [sodaHelper.account.address])
    if (!balance_sender_before){
        console.log("Failed to call the view function")
        return
    }
    console.log("Balance of the account:", balance_sender_before);

    const amount_to_transfer = 100
    receipt = await sodaHelper.callContractTransaction("Token", "transfer", [RECEIVER_ADDRESS, amount_to_transfer])
    if (!receipt){
        console.log("Failed to call the transaction function")
        return
    }
    console.log("Transaction successful with hash:", receipt.transactionHash)

    const balance_receiver_after = await sodaHelper.callContractView("Token", "balanceOf", [RECEIVER_ADDRESS])
    if (!balance_receiver_after){
        console.log("Failed to call the view function")
        return
    }
    console.log("Balance of the account:", balance_receiver_after);

    const balance_sender_after = await sodaHelper.callContractView("Token", "balanceOf", [sodaHelper.account.address])
    if (!balance_sender_after){
        console.log("Failed to call the view function")
        return
    }
    console.log("Balance of the account:", balance_sender_after);

}

main();