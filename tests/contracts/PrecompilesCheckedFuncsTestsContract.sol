// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestAbstract.sol";

contract PrecompilesCheckedFuncsTestsContract is TestAbstract {

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

    function checkedAddTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
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

        // Calculate all available checkedAdd functions for 128 bits
        check128.res128_128 =  MpcCore.checkedAdd(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.checkedAdd(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.checkedAdd(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.checkedAdd(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.checkedAdd(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.checkedAdd(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.checkedAdd(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.checkedAdd(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.checkedAdd(castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "checkedAddTest: cast 128 failed");

        // Calculate all available checkedAdd functions for 256 bits
        check256.res256_256 = MpcCore.checkedAdd(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.checkedAdd(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.checkedAdd(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.checkedAdd(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.checkedAdd(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.checkedAdd(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.checkedAdd(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.checkedAdd(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.checkedAdd(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.checkedAdd(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.checkedAdd(castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "checkedAddTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a8_s, b)),
                "checkedAddTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a16_s, b)),
                "checkedAddTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a32_s, b)),
                "checkedAddTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a64_s, b)),
                "checkedAddTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a128_s, b)),
                "checkedAddTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedAdd(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.checkedAdd(castingValues.a256_s, b)),
                "checkedAddTest: test 256 bits with scalar failed");

        return result;
    }

    function checkedSubTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
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

        // Calculate all available checkedSub functions for 128 bits
        check128.res128_128 =  MpcCore.checkedSub(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.checkedSub(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.checkedSub(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.checkedSub(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.checkedSub(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.checkedSub(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.checkedSub(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.checkedSub(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.checkedSub(castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "checkedSubTest: cast 128 failed");

        // Calculate all available checkedSub functions for 256 bits
        check256.res256_256 = MpcCore.checkedSub(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.checkedSub(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.checkedSub(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.checkedSub(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.checkedSub(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.checkedSub(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.checkedSub(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.checkedSub(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.checkedSub(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.checkedSub(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.checkedSub(castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "checkedSubTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a8_s, b)),
                "checkedSubTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a16_s, b)),
                "checkedSubTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a32_s, b)),
                "checkedSubTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a64_s, b)),
                "checkedSubTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a128_s, b)),
                "checkedSubTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.checkedSub(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.checkedSub(castingValues.a256_s, b)),
                "checkedSubTest: test 256 bits with scalar failed");

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
        require(result == MpcCore.decrypt(MpcCore.checkedMul(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.checkedMul(castingValues.a64_s, b)),
                "checkedMulTest: test 64 bits with scalar failed");
                
        return result;
    }
}