// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./MpcCore.sol";

// DeepContract is used to test the authenticated mechanism
contract DeepContract {
    uint256 public DeepContractStoredData;
    gtUint8 public DeepContractStoredSecretData;
    ctUint8 public DeepContractStoredSecretDataCt;
    // Define functions and state variables for AnotherContract
     function testSecondDepth(gtUint8 val) public returns (uint256) {
         DeepContractStoredSecretDataCt = MpcCore.offBoard(val);

        // Should work only if storedSecretDataCt was saved to secure memory 
        DeepContractStoredSecretData = MpcCore.onBoard(DeepContractStoredSecretDataCt); 
        DeepContractStoredData = MpcCore.decrypt(DeepContractStoredSecretData);

        return DeepContractStoredData;
    }

    function decSecretData() public returns (uint256) {
         // Should work only if storedSecretDataCt was saved to secure memory 
        DeepContractStoredSecretData = MpcCore.onBoard(DeepContractStoredSecretDataCt); 
        DeepContractStoredSecretData = MpcCore.add(DeepContractStoredSecretData,DeepContractStoredSecretData); 
        DeepContractStoredData = MpcCore.decrypt(DeepContractStoredSecretData);

        return DeepContractStoredData;
    }
}

contract TestSecureCts {
    uint256 public storedData;
    gtUint8 public storedSecretData;
    gtUint8 public storedSecretData8;
    ctUint8 public storedSecretDataCt;
    ctUint8 public stolenCt = ctUint8.wrap(103777073725655349389692396684366537432132510637571999534684058937703480557253);

     DeepContract deepContract;

    gtBool public storedSecretBool;

    function SetX(uint256 x) public {
        storedData = x;
    }

    function GetX() public view returns (uint256) {
        return storedData;
    }

    function GetSecretX() public view returns (gtUint8) {
        return storedSecretData;
    }


    function SetCt(ctUint8 ct) public {
        storedSecretDataCt = ct;
    }

    function GetCt() public view returns (ctUint8) {
        return storedSecretDataCt;
    }

    
    function createContractDeepContract() public {
        // Deploy a new instance of ContractB
        deepContract = new DeepContract();
    }

    
    function testDeep(uint8 val) public {

        gtUint8 a = MpcCore.setPublic8(val);
        gtUint8 c = MpcCore.add(a,a); 

        storedData = deepContract.testSecondDepth(c); // Call the desired function

    }

    function testDeepStoredData(uint8 val) public {

        storedData =  deepContract.decSecretData(); // Call the desired function
    }

    function setGeneratedCtToSecureStorage(uint8 val) public {

        gtUint8 a = MpcCore.setPublic8(val);
        gtUint8 c = MpcCore.add(a,a); // 10
    
        // should store cipher-text to secure storage as this data is off-boarded
        storedSecretDataCt = MpcCore.offBoard(c);

        // Should work only if storedSecretDataCt was saved to secure memory 
        storedSecretData = MpcCore.onBoard(storedSecretDataCt); 
        storedData = MpcCore.decrypt(storedSecretData);//10
    }

    // Call after setGeneratedCtToSecureStorage
    function onBoradFromSecureStorage() public {
        // Should work only if storedSecretDataCt was saved to secure memory 
        gtUint8 a = MpcCore.onBoard(storedSecretDataCt); //10

        storedSecretData = MpcCore.add(a, a); //20
        storedSecretData = MpcCore.add(storedSecretData, storedSecretData); //40

        // should store cipher-text to secure storage as this data is off-boarded
        storedSecretDataCt = MpcCore.offBoard(storedSecretData);

        gtUint8 val = MpcCore.onBoard(storedSecretDataCt); 
        storedData = MpcCore.decrypt(storedSecretData);//40
    }

    // Call after setGeneratedCtToSecureStorage
    function tryOnBoradStolenStorage() public {
        storedData = 0;

        // Stolen cipher-text, should not be on-boarded
        gtUint8 a = MpcCore.onBoard(stolenCt); 

        storedSecretData = MpcCore.add(a, a); 
        storedData = MpcCore.decrypt(storedSecretData);
    }

    function tryOnBoradStolenMemory() public {
        storedData = 0;

        // Stolen cipher-text, should not be on-boarded
        ctUint8 localStolenCt = ctUint8.wrap(79057359674819555941801408421876086364881945436693532756088648266522594097508);

        gtUint8 a = MpcCore.onBoard(localStolenCt); 

        storedSecretData = MpcCore.add(a, a); 
        storedData = MpcCore.decrypt(storedSecretData);
    }
}
