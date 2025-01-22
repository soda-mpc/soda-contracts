import fs from 'fs';
import {privateToAddress} from 'ethereumjs-util';
import {generateECDSAPrivateKey} from 'soda-sdk';

// Generate ECDSA private key
const privateKey = generateECDSAPrivateKey().toString('hex');

// Create account address from private key
const address = privateToAddress(Buffer.from(privateKey, 'hex')).toString('hex');

console.log("Account address: ", '0x'+ address);

// Write the data to a .env file
fs.appendFileSync('.env', `export SIGNING_KEY='0x${privateKey}'\n`);
