// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesCheckedWithOverflowFuncsTestsContract {

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
        gtBool overflowBit1;
        gtUint16 res8_16;
        gtBool overflowBit2;
        gtUint16 res16_8;
        gtBool overflowBit3;
    }

    struct Check32 {
        gtUint32 res32_32;
        gtBool overflowBit1;
        gtUint32 res8_32;
        gtBool overflowBit2;
        gtUint32 res32_8;
        gtBool overflowBit3;
        gtUint32 res16_32;
        gtBool overflowBit4;
        gtUint32 res32_16;
        gtBool overflowBit5;
    }

    struct Check64 {
        gtUint64 res64_64;
        gtBool overflowBit1;
        gtUint64 res8_64;
        gtBool overflowBit2;
        gtUint64 res64_8;
        gtBool overflowBit3;
        gtUint64 res16_64;
        gtBool overflowBit4;
        gtUint64 res64_16;
        gtBool overflowBit5;
        gtUint64 res32_64;
        gtBool overflowBit6;
        gtUint64 res64_32;
        gtBool overflowBit7;
    }

    uint8 addResult;
    bool addOverflowBit;
    bool addOverflow;
    uint8 subResult;
    bool subOverflowBit;
    bool subOverflow;


    function getAddResult() public view returns (bool, uint8) {
        return (addOverflowBit, addResult);
    }

    function getAddOverflow() public view returns (bool) {
        return addOverflow;
    }

    function getSubResult() public view returns (bool, uint8) {
        return (subOverflowBit, subResult);
    }

    function getSubOverflow() public view returns (bool) {
        return subOverflow;
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

    function decryptAndCompareResults16(Check16 memory check16) public returns (bool, uint16){

        // Calculate the result
        uint16 result = MpcCore.decrypt(check16.res16_16);
        bool overflowBit = MpcCore.decrypt(check16.overflowBit1);

        require(result == MpcCore.decrypt(check16.res8_16) && result == MpcCore.decrypt(check16.res16_8) 
                && overflowBit == MpcCore.decrypt(check16.overflowBit2) && overflowBit == MpcCore.decrypt(check16.overflowBit3), 
                                "decryptAndCompareAllResults: Failed to decrypt and compare all results");
        return (overflowBit, result);
    }

    function decryptAndCompareResults32(Check32 memory check32) public returns (bool, uint32){

        // Calculate the result
        uint32 result = MpcCore.decrypt(check32.res32_32);
        bool overflowBit = MpcCore.decrypt(check32.overflowBit1);

        require(result == MpcCore.decrypt(check32.res8_32) && result == MpcCore.decrypt(check32.res32_8) 
                && result == MpcCore.decrypt(check32.res32_16) && result == MpcCore.decrypt(check32.res16_32)
                && overflowBit == MpcCore.decrypt(check32.overflowBit2) && overflowBit == MpcCore.decrypt(check32.overflowBit3)
                && overflowBit == MpcCore.decrypt(check32.overflowBit4) && overflowBit == MpcCore.decrypt(check32.overflowBit5), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return (overflowBit, result);
    }

    function decryptAndCompareResults64(Check64 memory check64) public returns (bool, uint64){

        // Calculate the result
        uint64 result = MpcCore.decrypt(check64.res64_64);
        bool overflowBit = MpcCore.decrypt(check64.overflowBit1);

        require(result == MpcCore.decrypt(check64.res8_64) && result == MpcCore.decrypt(check64.res64_8) 
                && result == MpcCore.decrypt(check64.res64_16) && result == MpcCore.decrypt(check64.res16_64)
                && result == MpcCore.decrypt(check64.res64_32) && result == MpcCore.decrypt(check64.res32_64)
                && overflowBit == MpcCore.decrypt(check64.overflowBit2) && overflowBit == MpcCore.decrypt(check64.overflowBit3)
                && overflowBit == MpcCore.decrypt(check64.overflowBit4) && overflowBit == MpcCore.decrypt(check64.overflowBit5)
                && overflowBit == MpcCore.decrypt(check64.overflowBit6) && overflowBit == MpcCore.decrypt(check64.overflowBit7), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return (overflowBit, result);
    }

    function checkedAddWithOverflowBitTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        (gtBool overflowBit8, gtUint8 res) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, castingValues.b8_s);
        addResult = MpcCore.decrypt(res);
        addOverflowBit = MpcCore.decrypt(overflowBit8);
    
        // Calculate the results with casting to 16
        (check16.overflowBit1, check16.res16_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, castingValues.b16_s);
        (check16.overflowBit2, check16.res8_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, castingValues.b16_s);
        (check16.overflowBit3, check16.res16_8) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, castingValues.b8_s);
        (bool overflowBit16, uint16 res16) = decryptAndCompareResults16(check16);
        require(res16 == addResult && overflowBit16 == addOverflowBit, "checkedAddWithOverflowBitTest: cast 16 failed");

        // Calculate the result with casting to 32
        (check32.overflowBit1, check32.res32_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, castingValues.b32_s);
        (check32.overflowBit2, check32.res8_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, castingValues.b32_s);
        (check32.overflowBit3, check32.res32_8) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, castingValues.b8_s);
        (check32.overflowBit4, check32.res16_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, castingValues.b32_s);
        (check32.overflowBit5, check32.res32_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, castingValues.b16_s);
        (bool overflowBit32, uint32 res32) = decryptAndCompareResults32(check32);
        require(addResult == res32 && overflowBit32 == addOverflowBit, "checkedAddWithOverflowBitTest: cast 32 failed");

        // Calculate the result with casting to 64
        (check64.overflowBit1, check64.res64_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, castingValues.b64_s);
        (check64.overflowBit2, check64.res8_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, castingValues.b64_s);
        (check64.overflowBit3, check64.res64_8) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, castingValues.b8_s);
        (check64.overflowBit4, check64.res16_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, castingValues.b64_s);
        (check64.overflowBit5, check64.res64_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, castingValues.b16_s);
        (check64.overflowBit6, check64.res32_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, castingValues.b64_s);
        (check64.overflowBit7, check64.res64_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, castingValues.b32_s);
        (bool overflowBit64, uint64 res64) = decryptAndCompareResults64(check64);
        require(addResult == res64 && overflowBit64 == addOverflowBit, "checkedAddWithOverflowBitTest: cast 64 failed");

        // Check the result with scalar
        (overflowBit8, res) = MpcCore.checkedAddWithOverflowBit(a, castingValues.b8_s);
        require(addResult == MpcCore.decrypt(res) && addOverflowBit == MpcCore.decrypt(overflowBit8), 
                "checkedAddWithOverflowBitTest: test 8 bits with scalar failed");
        (overflowBit8, res) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, b);
        require(addResult == MpcCore.decrypt(res) && addOverflowBit == MpcCore.decrypt(overflowBit8), 
                "checkedAddWithOverflowBitTest: test 8 bits with scalar failed");
        (check16.overflowBit1, check16.res16_16) = MpcCore.checkedAddWithOverflowBit(a, castingValues.b16_s);
        require(addResult == MpcCore.decrypt(check16.res16_16) && addOverflowBit == MpcCore.decrypt(check16.overflowBit1), 
                "checkedAddWithOverflowBitTest: test 16 bits with scalar failed");
        (check16.overflowBit1, check16.res16_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, b);
        require(addResult == MpcCore.decrypt(check16.res16_16) && addOverflowBit == MpcCore.decrypt(check16.overflowBit1), 
                "checkedAddWithOverflowBitTest: test 16 bits with scalar failed");
        (check32.overflowBit1, check32.res32_32) = MpcCore.checkedAddWithOverflowBit(a, castingValues.b32_s);
        require(addResult == MpcCore.decrypt(check32.res32_32) && addOverflowBit == MpcCore.decrypt(check32.overflowBit1),
                "checkedAddWithOverflowBitTest: test 32 bits with scalar failed");
        (check32.overflowBit1, check32.res32_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, b);
        require(addResult == MpcCore.decrypt(check32.res32_32) && addOverflowBit == MpcCore.decrypt(check32.overflowBit1),
                "checkedAddWithOverflowBitTest: test 32 bits with scalar failed");
        (check64.overflowBit1, check64.res64_64) = MpcCore.checkedAddWithOverflowBit(a, castingValues.b64_s);
        require(addResult == MpcCore.decrypt(check64.res64_64) && addOverflowBit == MpcCore.decrypt(check64.overflowBit1), 
                "checkedAddWithOverflowBitTest: test 64 bits with scalar failed");
        (check64.overflowBit1, check64.res64_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, b);
        require(addResult == MpcCore.decrypt(check64.res64_64) && addOverflowBit == MpcCore.decrypt(check64.overflowBit1), 
                "checkedAddWithOverflowBitTest: test 64 bits with scalar failed");

        return addResult;
    }

    // This test is used to check cases where the addition of two numbers will overflow
    function checkedAddOverflowTest(uint8 a, uint8 b, uint16 a16, uint16 b16, uint32 a32, uint32 b32, uint64 a64, uint64 b64) public {
        gtUint8 a_s = MpcCore.setPublic8(a);
        gtUint8 b_s = MpcCore.setPublic8(b);

        gtUint16 a_s16 = MpcCore.setPublic16(a16);
        gtUint16 b_s16 = MpcCore.setPublic16(b16);

        gtUint32 a_s32 = MpcCore.setPublic32(a32);
        gtUint32 b_s32 = MpcCore.setPublic32(b32);

        gtUint64 a_s64 = MpcCore.setPublic64(a64);
        gtUint64 b_s64 = MpcCore.setPublic64(b64);
        
        // Calculate addition with overflow for all sizes
        (gtBool overflowBit8, gtUint8 res) = MpcCore.checkedAddWithOverflowBit(a_s, b_s);
        (gtBool overflowBit16, gtUint16 res16) = MpcCore.checkedAddWithOverflowBit(a_s16, b_s16);
        (gtBool overflowBit32, gtUint32 res32) = MpcCore.checkedAddWithOverflowBit(a_s32, b_s32);
        (gtBool overflowBit64, gtUint64 res64) = MpcCore.checkedAddWithOverflowBit(a_s64, b_s64);

        // All overflow bits should be true, so AND them together should give true
        addOverflow = MpcCore.decrypt(overflowBit8) && MpcCore.decrypt(overflowBit16) && MpcCore.decrypt(overflowBit32) && MpcCore.decrypt(overflowBit64);
    }

    function checkedSubWithOverflowBitTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        (gtBool overflowBit8, gtUint8 res) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, castingValues.b8_s);
        subResult = MpcCore.decrypt(res);
        subOverflowBit = MpcCore.decrypt(overflowBit8);
    
        // Calculate the results with casting to 16
        (check16.overflowBit1, check16.res16_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, castingValues.b16_s);
        (check16.overflowBit2, check16.res8_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, castingValues.b16_s);
        (check16.overflowBit3, check16.res16_8) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, castingValues.b8_s);
        (bool overflowBit16, uint16 res16) = decryptAndCompareResults16(check16);
        require(res16 == subResult && overflowBit16 == subOverflowBit, "checkedSubWithOverflowBitTest: cast 16 failed");

        // Calculate the result with casting to 32
        (check32.overflowBit1, check32.res32_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, castingValues.b32_s);
        (check32.overflowBit2, check32.res8_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, castingValues.b32_s);
        (check32.overflowBit3, check32.res32_8) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, castingValues.b8_s);
        (check32.overflowBit4, check32.res16_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, castingValues.b32_s);
        (check32.overflowBit5, check32.res32_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, castingValues.b16_s);
        (bool overflowBit32, uint32 res32) = decryptAndCompareResults32(check32);
        require(subResult == res32 && overflowBit32 == subOverflowBit, "checkedSubWithOverflowBitTest: cast 32 failed");

        // Calculate the result with casting to 64
        (check64.overflowBit1, check64.res64_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, castingValues.b64_s);
        (check64.overflowBit2, check64.res8_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, castingValues.b64_s);
        (check64.overflowBit3, check64.res64_8) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, castingValues.b8_s);
        (check64.overflowBit4, check64.res16_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, castingValues.b64_s);
        (check64.overflowBit5, check64.res64_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, castingValues.b16_s);
        (check64.overflowBit6, check64.res32_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, castingValues.b64_s);
        (check64.overflowBit7, check64.res64_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, castingValues.b32_s);
        (bool overflowBit64, uint64 res64) = decryptAndCompareResults64(check64);
        require(subResult == res64 && overflowBit64 == subOverflowBit, "checkedSubWithOverflowBitTest: cast 64 failed");

        // Check the result with scalar
        (overflowBit8, res) = MpcCore.checkedSubWithOverflowBit(a, castingValues.b8_s);
        require(subResult == MpcCore.decrypt(res) && subOverflowBit == MpcCore.decrypt(overflowBit8), 
                "checkedSubWithOverflowBitTest: test 8 bits with scalar failed");
        (overflowBit8, res) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, b);
        require(subResult == MpcCore.decrypt(res) && subOverflowBit == MpcCore.decrypt(overflowBit8), 
                "checkedSubWithOverflowBitTest: test 8 bits with scalar failed");
        (check16.overflowBit1, check16.res16_16) = MpcCore.checkedSubWithOverflowBit(a, castingValues.b16_s);
        require(subResult == MpcCore.decrypt(check16.res16_16) && subOverflowBit == MpcCore.decrypt(check16.overflowBit1), 
                "checkedSubWithOverflowBitTest: test 16 bits with scalar failed");
        (check16.overflowBit1, check16.res16_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, b);
        require(subResult == MpcCore.decrypt(check16.res16_16) && subOverflowBit == MpcCore.decrypt(check16.overflowBit1), 
                "checkedSubWithOverflowBitTest: test 16 bits with scalar failed");
        (check32.overflowBit1, check32.res32_32) = MpcCore.checkedSubWithOverflowBit(a, castingValues.b32_s);
        require(subResult == MpcCore.decrypt(check32.res32_32) && subOverflowBit == MpcCore.decrypt(check32.overflowBit1),
                "checkedSubWithOverflowBitTest: test 32 bits with scalar failed");
        (check32.overflowBit1, check32.res32_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, b);
        require(subResult == MpcCore.decrypt(check32.res32_32) && subOverflowBit == MpcCore.decrypt(check32.overflowBit1),
                "checkedSubWithOverflowBitTest: test 32 bits with scalar failed");
        (check64.overflowBit1, check64.res64_64) = MpcCore.checkedSubWithOverflowBit(a, castingValues.b64_s);
        require(subResult == MpcCore.decrypt(check64.res64_64) && subOverflowBit == MpcCore.decrypt(check64.overflowBit1), 
                "checkedSubWithOverflowBitTest: test 64 bits with scalar failed");
        (check64.overflowBit1, check64.res64_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, b);
        require(subResult == MpcCore.decrypt(check64.res64_64) && subOverflowBit == MpcCore.decrypt(check64.overflowBit1), 
                "checkedSubWithOverflowBitTest: test 64 bits with scalar failed");

        return subResult;
    }

    // This test is used to check cases where the subtraction of two numbers will overflow
    function checkedSubOverflowTest(uint8 a, uint8 b) public {
        gtUint8 a_s = MpcCore.setPublic8(a);
        gtUint8 b_s = MpcCore.setPublic8(b);

        gtUint16 a_s16 = MpcCore.setPublic16(a);
        gtUint16 b_s16 = MpcCore.setPublic16(b);

        gtUint32 a_s32 = MpcCore.setPublic32(a);
        gtUint32 b_s32 = MpcCore.setPublic32(b);

        gtUint64 a_s64 = MpcCore.setPublic64(a);
        gtUint64 b_s64 = MpcCore.setPublic64(b);
        
        // Calculate addition with overflow for all sizes
        (gtBool overflowBit8, gtUint8 res) = MpcCore.checkedSubWithOverflowBit(a_s, b_s);
        (gtBool overflowBit16, gtUint16 res16) = MpcCore.checkedSubWithOverflowBit(a_s16, b_s16);
        (gtBool overflowBit32, gtUint32 res32) = MpcCore.checkedSubWithOverflowBit(a_s32, b_s32);
        (gtBool overflowBit64, gtUint64 res64) = MpcCore.checkedSubWithOverflowBit(a_s64, b_s64);

        // All overflow bits should be true, so AND them together should give true
        subOverflow = MpcCore.decrypt(overflowBit8) && MpcCore.decrypt(overflowBit16) && MpcCore.decrypt(overflowBit32) && MpcCore.decrypt(overflowBit64);
    }

}