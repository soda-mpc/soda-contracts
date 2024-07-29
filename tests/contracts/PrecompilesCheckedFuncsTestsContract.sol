// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesCheckedFuncsTestsContract {

    struct AllGTCastingValues {
        gtUint8 a8_s;
        gtUint8 b8_s;
        gtUint16 a16_s;
        gtUint16 b16_s;
        gtUint32 a32_s;
        gtUint32 b32_s;
        gtUint64 a64_s;
        gtUint64 b64_s;
    }

    struct Check16 {
        gtUint16 res16_16;
        gtUint16 res8_16;
        gtUint16 res16_8;
    }

    struct Check32 {
        gtUint32 res32_32;
        gtUint32 res8_32;
        gtUint32 res32_8;
        gtUint32 res16_32;
        gtUint32 res32_16;
    }

    struct Check64 {
        gtUint64 res64_64;
        gtUint64 res8_64;
        gtUint64 res64_8;
        gtUint64 res16_64;
        gtUint64 res64_16;
        gtUint64 res32_64;
        gtUint64 res64_32;
    }

    uint8 addResult;
    uint8 subResult;
    uint8 mulResult;


    function getAddResult() public view returns (uint8) {
        return addResult;
    }

    function getSubResult() public view returns (uint8) {
        return subResult;
    }

    function getMulResult() public view returns (uint8) {
        return mulResult;
    }

    function setPublicValues(AllGTCastingValues memory castingValues, uint8 a, uint8 b) public{
        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);
        castingValues.a16_s =  MpcCore.setPublic16(a);
        castingValues.b16_s =  MpcCore.setPublic16(b);
        castingValues.a32_s =  MpcCore.setPublic32(a);
        castingValues.b32_s =  MpcCore.setPublic32(b);
        castingValues.a64_s =  MpcCore.setPublic64(a);
        castingValues.b64_s =  MpcCore.setPublic64(b);
    }

    function decryptAndCompareResults16(Check16 memory check16) public returns (uint16){

        // Calculate the result
        uint16 result = MpcCore.decrypt(check16.res16_16);

        require(result == MpcCore.decrypt(check16.res8_16) && result == MpcCore.decrypt(check16.res16_8), 
                                "decryptAndCompareAllResults: Failed to decrypt and compare all results");
        return result;
    }

    function decryptAndCompareResults32(Check32 memory check32) public returns (uint32){

        // Calculate the result
        uint32 result = MpcCore.decrypt(check32.res32_32);

        require(result == MpcCore.decrypt(check32.res8_32) && result == MpcCore.decrypt(check32.res32_8) 
                && result == MpcCore.decrypt(check32.res32_16) && result == MpcCore.decrypt(check32.res16_32), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults64(Check64 memory check64) public returns (uint64){

        // Calculate the result
        uint64 result = MpcCore.decrypt(check64.res64_64);

        require(result == MpcCore.decrypt(check64.res8_64) && result == MpcCore.decrypt(check64.res64_8) 
                && result == MpcCore.decrypt(check64.res64_16) && result == MpcCore.decrypt(check64.res16_64)
                && result == MpcCore.decrypt(check64.res64_32) && result == MpcCore.decrypt(check64.res32_64), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function checkedAddTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a8_s, castingValues.b8_s));
        addResult = result;
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.checkedAdd(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.checkedAdd(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.checkedAdd(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "checkedAddTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.checkedAdd(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.checkedAdd(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.checkedAdd(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.checkedAdd(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.checkedAdd(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "checkedAddTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.checkedAdd(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.checkedAdd(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.checkedAdd(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.checkedAdd(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.checkedAdd(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.checkedAdd(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.checkedAdd(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "checkedAddTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a8_s, b)),
                "checkedAddTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a16_s, b)),
                "checkedAddTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a32_s, b)),
                "checkedAddTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a64_s, b)),
                "checkedAddTest: test 64 bits with scalar failed");

        return result;
    }

    function checkedSubTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.checkedSub(castingValues.a8_s, castingValues.b8_s));
        subResult = result;
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.checkedSub(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.checkedSub(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.checkedSub(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "checkedSubTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.checkedSub(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.checkedSub(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.checkedSub(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.checkedSub(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.checkedSub(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "checkedSubTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.checkedSub(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.checkedSub(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.checkedSub(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.checkedSub(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.checkedSub(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.checkedSub(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.checkedSub(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "checkedSubTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a8_s, b)),
                "checkedSubTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a16_s, b)),
                "checkedSubTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a32_s, b)),
                "checkedSubTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a64_s, b)),
                "checkedSubTest: test 64 bits with scalar failed");

        return result;
    }

    function checkedMulTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.checkedMul(castingValues.a8_s, castingValues.b8_s));
        mulResult = result;
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.checkedMul(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.checkedMul(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.checkedMul(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "checkedMulTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.checkedMul(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.checkedMul(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.checkedMul(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.checkedMul(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.checkedMul(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "checkedMulTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.checkedMul(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.checkedMul(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.checkedMul(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.checkedMul(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.checkedMul(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.checkedMul(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.checkedMul(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "checkedMulTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.checkedMul(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.checkedMul(castingValues.a8_s, b)),
                "checkedMulTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedMul(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.checkedMul(castingValues.a16_s, b)),
                "checkedMulTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedMul(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.checkedMul(castingValues.a32_s, b)),
                "checkedMulTest: test 32 bits with scalar failed");
        // require(result == MpcCore.decrypt(MpcCore.checkedMul(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.checkedMul(castingValues.a64_s, b)),
        //         "checkedMulTest: test 64 bits with scalar failed");
                
        return result;
    }
}