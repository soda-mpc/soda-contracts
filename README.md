# Devnet
Welcome to the Soda bubble devnet, where smart contract privacy is finally made possible on the EVM.
Here you fill find all the tools and example that will help you get started.
Our network is typically reachable on `node.sodalabs.net:7000`, if you are already familiar
with smart contracts developments you could use any tool you are used to in order to interact with the Bubble devnet.

If you prefer using our tools for deploying and running EVM smart contracts, below you would find the instructions for
installing all the necessary dependencies for getting started. 

# Clone the Repository
```bash
git clone git@github.com:soda-mpc/devnet.git
```

# Installation Instructions

Follow these steps to install dependencies and build the necessary components for your project.

## Install Dependencies

### Python 3.9
Check installed python version
```bash
python3 --version
```

If your python is not 3.9 or 3.10
```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.9
```

#### Install Python Dependencies

```bash
python3 -m virtualenv sodanet
source sodanet/bin/activate
pip install -r requirements.txt
cd ..
```

#### Install Javascript Dependencies

```bash
npm install
```

### Solidity
For Solidity, use the curl command to download and install the stable version:

```bash
SOLC_VERSION="stable" && \
curl -L https://github.com/ethereum/solidity/releases/download/v${SOLC_VERSION}/solc-static-linux -o /usr/local/bin/solc && \
chmod +x /usr/local/bin/solc
```

# Getting started

## Onboard a new user

This step involves creating a new user account within the system. The user account will include cryptographic credentials, such as the private key of the account and AES key, which will be used for authentication and secure communication within the system.

### 1. Generate an account

This step generates a new private key and account.

* Script: The system provides a script (gen_account) written in both Python and JavaScript to facilitate the generation of user accounts.

* Execution: To execute the script, navigate to the main directory (Devnet) and run the appropriate command depending on the language choice:

    ```bash
    python3 -m onboardUser.scripts.python.gen_account
    ```

    or

    ```bash
    node onboardUser/scripts/js/gen_account.mjs
    ```

* Output: The script will create a new account and save the private key in a .env file in the user's file system.

* Environment Loading: The user should load the private key into their environment using the command:

    ```bash
    source .env
    ```

### 2. Get some coins

This step involves acquiring native coins or tokens that are required to interact with the system. The system provides a Telegram-built faucet for users to request tokens easily through simple commands and interactions within the Telegram chat interface.

* Faucet Interaction: Users can initiate a conversation with the system's bot and follow the prompts to receive tokens effortlessly.

### 3. Onboard the account to the system
Once the account is created and funded with native coins, it needs to be onboarded to the system to obtain an AES key. This AES key may be used for encryption and decryption purposes within the system.

* Script: The system provides a script (onboard_user) to facilitate the onboarding process.

* Execution: Similar to step 1, navigate to the main directory (Devnet) and run the appropriate command depending on the language choice:

    ```bash
    python3 -m onboardUser.scripts.python.onboard_user
    ```

    or

    ```bash
    node onboardUser/scripts/js/onboard_user.mjs
    ```

* Output: After running the script, an AES key is added to the .env file.

* Environment Loading: The user should load the AES key into their environment using the command:

    ```bash
    source .env
    ```

After completing steps 1-3, the user has a functional account with the necessary credentials and tokens, allowing them to start interacting with the system, including running smart contracts or performing other actions as needed.

# Runnnig Examples

## Private ERC20

We provide an example for ERC20 token standard with enhanced privacy features. 
It aims to ensure the confidentiality of token transactions through encryption techniques while maintaining compatibility with the ERC20 standard.
 
### Key Features:
* Privacy Enhancement:
    The contract utilizes encryption techniques to encrypt sensitive data such as token balances and allowances. Encryption is performed using both user-specific and system-wide encryption keys to safeguard transaction details.
* Encrypted Balances and Allowances:
    Token balances and allowances are stored in encrypted form within the contract's state variables. This ensures that sensitive information remains confidential and inaccessible to unauthorized parties.
* Integration with MPC Core:
    The contract leverages functionalities provided by an external component called MpcCore. This component likely implements cryptographic operations such as encryption, decryption, and signature verification using techniques like Multi-Party Computation (MPC).
* Token Transfer Methods:
    The contract provides multiple transfer methods, allowing token transfers in both encrypted and clear (unencrypted) forms. Transfers can occur between addresses with encrypted token values or clear token values.
* Approval Mechanism:
    An approval mechanism is implemented to allow token holders to grant spending permissions (allowances) to other addresses. Approvals are also encrypted to maintain transaction privacy.

### Usage 

* Script: The system provides a script (run_private_erc20) to run the example in both Python and JavaScript languages. 
The run_private_erc20 script is designed to demonstrate the functionality of ERC20 tokens within the system. It includes functionalities such as transferring tokens, approving token transactions, and checking token balances.

* Execution: Navigate to the main directory (Devnet) and run the appropriate command depending on the language choice:

    ```bash
    python3 -m examples.scripts.python.run_private_erc20
    ```

    or

    ```bash
    node examples/scripts/js/run_private_erc20.mjs
    ```

* Script output: Upon execution, the script will perform various ERC20 functionalities, such as transferring tokens, approving transactions, and retrieving token balances. The output of these operations will be printed to the terminal or command prompt screen.

* Conclusion: By following these steps, you'll be able to execute the run_private_erc20 script and observe the private ERC20 functionalities in action. This provides a practical demonstration of how private ERC20 tokens work within the system and allows you to understand their behavior and usage within your project.

# Running tests

The tests script is designed to verify all supported functionalities of sodalabs

## Usage

* Script: The provided script run_precompile_tests_contract.py serves the purpose of running tests for sodalabs. These tests likely cover a range of functionalities and scenarios to ensure the correctness and robustness of the sodalabs system.

* Execution Instructions:
To execute the tests script, follow these steps:

    * Navigate to Main Directory (Devnet):

        Open your terminal or command prompt and navigate to the main directory of your project, which is named Devnet.

    * Execute the Script:

        Run the following command to execute the tests script:

        ```bash
        python3 -m tests.scripts.python.run_precompile_tests_contract
        ```

* Script Output:
Upon execution, the script will run various tests, such as addition, multiplication, random generation, transfers, and more. The output of these tests will be displayed on the terminal or command prompt screen.

* Conclusion
By following these steps, you can execute the tests script to ensure that all functionalities of sodalabs are working correctly. The tests provide confidence in the reliability and accuracy of the system's functionalities, helping to maintain the quality and stability of the sodalabs platform.

