// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestAbstract.sol";    

contract PrecompilesMinMaxTestsContract is TestAbstract {

    uint8 minResult;
    uint8 maxResult;

    function getMinResult() public view returns (uint8) {
        return minResult;
    }
    function getMaxResult() public view returns (uint8) {
        return maxResult;
    }

    

    function minTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.min(castingValues.a8_s, castingValues.b8_s));
        minResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.min(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.min(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.min(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "minTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.min(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.min(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.min(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.min(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.min(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "minTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.min(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.min(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.min(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.min(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.min(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.min(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.min(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "minTest: cast 64 failed");

        // Calculate all available min functions for 128 bits
        check128.res128_128 =  MpcCore.min(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.min(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.min(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.min(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.min(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.min(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.min(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.min(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.min(castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "minTest: cast 128 failed");

        // Calculate all available min functions for 256 bits
        check256.res256_256 = MpcCore.min(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.min(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.min(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.min(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.min(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.min(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.min(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.min(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.min(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.min(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.min(castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "minTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.min(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.min(castingValues.a8_s, b)),
                "minTest: test 8 bits with scalar failed");
        require(res16 == MpcCore.decrypt(MpcCore.min(a, castingValues.b16_s)) && res16 == MpcCore.decrypt(MpcCore.min(castingValues.a16_s, b)),
                "minTest: test 16 bits with scalar failed");
        require(res32 == MpcCore.decrypt(MpcCore.min(a, castingValues.b32_s)) && res32 == MpcCore.decrypt(MpcCore.min(castingValues.a32_s, b)),
                "minTest: test 32 bits with scalar failed");
        require(res64 == MpcCore.decrypt(MpcCore.min(a, castingValues.b64_s)) && res64 == MpcCore.decrypt(MpcCore.min(castingValues.a64_s, b)),
                "minTest: test 64 bits with scalar failed");
        require(res128 == MpcCore.decrypt(MpcCore.min(a, castingValues.b128_s)) && res128 == MpcCore.decrypt(MpcCore.min(castingValues.a128_s, b)),
                "minTest: test 128 bits with scalar failed");
        require(res256 == MpcCore.decrypt(MpcCore.min(a, castingValues.b256_s)) && res256 == MpcCore.decrypt(MpcCore.min(castingValues.a256_s, b)),
                "minTest: test 256 bits with scalar failed");

        return result;
    }

    function maxTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.max(castingValues.a8_s, castingValues.b8_s));
        maxResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.max(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.max(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.max(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "maxTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.max(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.max(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.max(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.max(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.max(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "maxTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.max(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.max(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.max(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.max(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.max(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.max(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.max(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "maxTest: cast 64 failed");

        // Calculate all available max functions for 128 bits
        check128.res128_128 =  MpcCore.max(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.max(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.max(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.max(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.max(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.max(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.max(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.max(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.max(castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "maxTest: cast 128 failed");

        // Calculate all available max functions for 256 bits
        check256.res256_256 = MpcCore.max(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.max(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.max(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.max(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.max(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.max(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.max(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.max(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.max(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.max(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.max(castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "maxTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.max(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.max(castingValues.a8_s, b)),
                "minTest: test 8 bits with scalar failed");
        require(res16 == MpcCore.decrypt(MpcCore.max(a, castingValues.b16_s)) && res16 == MpcCore.decrypt(MpcCore.max(castingValues.a16_s, b)),
                "minTest: test 16 bits with scalar failed");
        require(res32 == MpcCore.decrypt(MpcCore.max(a, castingValues.b32_s)) && res32 == MpcCore.decrypt(MpcCore.max(castingValues.a32_s, b)),
                "minTest: test 32 bits with scalar failed");
        require(res64 == MpcCore.decrypt(MpcCore.max(a, castingValues.b64_s)) && res64 == MpcCore.decrypt(MpcCore.max(castingValues.a64_s, b)),
                "minTest: test 64 bits with scalar failed");
        require(res128 == MpcCore.decrypt(MpcCore.max(a, castingValues.b128_s)) && res128 == MpcCore.decrypt(MpcCore.max(castingValues.a128_s, b)),
                "minTest: test 128 bits with scalar failed");
        require(res256 == MpcCore.decrypt(MpcCore.max(a, castingValues.b256_s)) && res256 == MpcCore.decrypt(MpcCore.max(castingValues.a256_s, b)),
                "minTest: test 256 bits with scalar failed");

        return result;
    }

}