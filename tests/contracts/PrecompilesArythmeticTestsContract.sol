// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestAbstract.sol";

contract PrecompilesArythmeticTestsContract is TestAbstract {

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

    function addTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.add(castingValues.a8_s, castingValues.b8_s));
        addResult = result;
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.add(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.add(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.add(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "addTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.add(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.add(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.add(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.add(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.add(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "addTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.add(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.add(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.add(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.add(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.add(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.add(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.add(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "addTest: cast 64 failed");

        // Calculate all available add functions for 128 bits
        check128.res128_128 =  MpcCore.add(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.add(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.add(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.add(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.add(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.add(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.add(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.add(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.add(castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "addTest: cast 128 failed");

        // Calculate all available add functions for 256 bits
        check256.res256_256 = MpcCore.add(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.add(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.add(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.add(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.add(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.add(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.add(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.add(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.add(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.add(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.add(castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "addTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a8_s, b)),
                "addTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a16_s, b)),
                "addTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a32_s, b)),
                "addTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a64_s, b)),
                "addTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a128_s, b)),
                "addTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.add(castingValues.a256_s, b)),
                "addTest: test 256 bits with scalar failed");

        return result;
    }

    function subTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.sub(castingValues.a8_s, castingValues.b8_s));
        subResult = result;
    
        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.sub(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.sub(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.sub(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "subTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.sub(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.sub(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.sub(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.sub(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.sub(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "subTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.sub(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.sub(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.sub(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.sub(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.sub(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.sub(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.sub(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "subTest: cast 64 failed");

        // Calculate all available sub functions for 128 bits
        check128.res128_128 =  MpcCore.sub(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.sub(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.sub(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.sub(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.sub(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.sub(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.sub(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.sub(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.sub(castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "subTest: cast 128 failed");

        // Calculate all available sub functions for 256 bits
        check256.res256_256 = MpcCore.sub(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.sub(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.sub(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.sub(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.sub(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.sub(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.sub(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.sub(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.sub(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.sub(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.sub(castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "subTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a8_s, b)),
                "subTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a16_s, b)),
                "subTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a32_s, b)),
                "subTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a64_s, b)),
                "subTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a128_s, b)),
                "subTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.sub(castingValues.a256_s, b)),
                "subTest: test 256 bits with scalar failed");

        return result;
    }

    function mulTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        mulResult = MpcCore.decrypt(MpcCore.mul(castingValues.a8_s, castingValues.b8_s));
        
        // Calculate the result with casting to 16
        check16.res16_16 = MpcCore.mul(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.mul(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.mul(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(mulResult == res16, "mulTest: cast 16 failed");
        
        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.mul(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.mul(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.mul(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.mul(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.mul(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(mulResult == res32, "mulTest: cast 32 failed");
        
        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.mul(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.mul(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.mul(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.mul(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.mul(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.mul(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.mul(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(mulResult == res64, "mulTest: cast 64 failed");
        
        // Check the result with scalar
        require(mulResult == MpcCore.decrypt(MpcCore.mul(a, castingValues.b8_s)) && mulResult == MpcCore.decrypt(MpcCore.mul(castingValues.a8_s, b)),
                "mulTest: test 8 bits with scalar failed");
        require(mulResult == MpcCore.decrypt(MpcCore.mul(a, castingValues.b16_s)) && mulResult == MpcCore.decrypt(MpcCore.mul(castingValues.a16_s, b)),
                "mulTest: test 16 bits with scalar failed");
        require(mulResult == MpcCore.decrypt(MpcCore.mul(a, castingValues.b32_s)) && mulResult == MpcCore.decrypt(MpcCore.mul(castingValues.a32_s, b)),
                "mulTest: test 32 bits with scalar failed");
        require(mulResult == MpcCore.decrypt(MpcCore.mul(a, castingValues.b64_s)) && mulResult == MpcCore.decrypt(MpcCore.mul(castingValues.a64_s, b)),
                "mulTest: test 64 bits with scalar failed");

        return mulResult;
    }
}