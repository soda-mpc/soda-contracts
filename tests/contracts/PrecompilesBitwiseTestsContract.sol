// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestAbstract.sol";

contract PrecompilesBitwiseTestsContract is TestAbstract {

    uint8 andResult;
    uint8 orResult;
    
    function getAndResult() public view returns (uint8) {
        return andResult;
    }
    function getOrResult() public view returns (uint8) {
        return orResult;
    }
    
    function andTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.and(castingValues.a8_s, castingValues.b8_s));
        andResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.and(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.and(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.and(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "andTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.and(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.and(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.and(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.and(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.and(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "andTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.and(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.and(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.and(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.and(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.and(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.and(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.and(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "andTest: cast 64 failed");

        // Calculate all available and functions for 128 bits
        check128.res128_128 =  MpcCore.and(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.and(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.and(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.and(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.and(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.and(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.and(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.and(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.and(castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "andTest: cast 128 failed");

        // Calculate all available and functions for 256 bits
        check256.res256_256 = MpcCore.and(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.and(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.and(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.and(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.and(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.and(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.and(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.and(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.and(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.and(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.and(castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "andTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.and(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.and(castingValues.a8_s, b)),
                "andTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.and(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.and(castingValues.a16_s, b)),
                "andTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.and(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.and(castingValues.a32_s, b)),
                "andTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.and(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.and(castingValues.a64_s, b)),
                "andTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.and(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.and(castingValues.a128_s, b)),
                "andTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.and(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.and(castingValues.a256_s, b)),
                "andTest: test 256 bits with scalar failed");

        return result;
    }

    function orTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.or(castingValues.a8_s, castingValues.b8_s));
        orResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.or(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.or(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.or(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "orTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.or(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.or(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.or(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.or(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.or(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "orTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.or(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.or(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.or(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.or(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.or(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.or(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.or(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "orTest: cast 64 failed");

        // Calculate all available or functions for 128 bits
        check128.res128_128 =  MpcCore.or(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.or(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.or(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.or(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.or(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.or(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.or(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.or(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.or(castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "orTest: cast 128 failed");

        // Calculate all available or functions for 256 bits
        check256.res256_256 = MpcCore.or(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.or(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.or(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.or(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.or(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.or(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.or(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.or(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.or(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.or(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.or(castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "orTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.or(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.or(castingValues.a8_s, b)),
                "orTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.or(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.or(castingValues.a16_s, b)),
                "orTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.or(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.or(castingValues.a32_s, b)),
                "orTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.or(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.or(castingValues.a64_s, b)),
                "orTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.or(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.or(castingValues.a128_s, b)),
                "orTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.or(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.or(castingValues.a256_s, b)),
                "orTest: test 256 bits with scalar failed");

        return result;
    }

}