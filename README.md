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
cd deploy_and_test
python3 -m virtualenv sodanet
source sodanet/bin/activate
pip install -r requirements.txt
cd ..
```

### Solidity
For Solidity, use the curl command to download and install the stable version:

```bash
SOLC_VERSION="stable" && \
curl -L https://github.com/ethereum/solidity/releases/download/v${SOLC_VERSION}/solc-static-linux -o /usr/local/bin/solc && \
chmod +x /usr/local/bin/solc
```



