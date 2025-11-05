// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestBoolAbstract.sol";

contract PrecompilesComparison1TestsContract is TestBoolAbstract {

    bool gtResult;
    bool leResult;

    function getGtResult() public view returns (bool) {
        return gtResult;
    }

    function getLeResult() public view returns (bool) {
        return leResult;
    }

    function gtTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        bool result =  MpcCore.decrypt(MpcCore.gt(castingValues.a8_s, castingValues.b8_s));
        gtResult = result;
    
        // Calculate the results with cating to 16
        check16.res16_16 = MpcCore.gt(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.gt(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.gt(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "gtTest: cast 16 failed");

        // Calculate the result with cating to 32
        check32.res32_32 = MpcCore.gt(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.gt(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.gt(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.gt(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.gt(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "gtTest: cast 32 failed");

        // Calculate the result with cating to 64
        check64.res64_64 = MpcCore.gt(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.gt(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.gt(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.gt(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.gt(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.gt(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.gt(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "gtTest: cast 64 failed");

        // Calculate all available gt functions for 128 bits
        check128.res128_128 =  MpcCore.gt(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.gt(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.gt(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.gt(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.gt(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.gt(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.gt(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.gt(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.gt(castingValues.a128_s, castingValues.b64_s);
        bool res128 = decryptAndCompareResults128(check128);
        require(result == res128, "gtTest: cast 128 failed");

        // Calculate all available gt functions for 256 bits
        check256.res256_256 = MpcCore.gt(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.gt(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.gt(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.gt(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.gt(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.gt(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.gt(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.gt(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.gt(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.gt(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.gt(castingValues.a256_s, castingValues.b128_s);
        bool res256 = decryptAndCompareResults256(check256);
        require(result == res256, "gtTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.gt(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.gt(castingValues.a8_s, b)),
                "gtTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.gt(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.gt(castingValues.a16_s, b)),
                "gtTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.gt(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.gt(castingValues.a32_s, b)),
                "gtTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.gt(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.gt(castingValues.a64_s, b)),
                "gtTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.gt(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.gt(castingValues.a128_s, b)),
                "gtTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.gt(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.gt(castingValues.a256_s, b)),
                "gtTest: test 256 bits with scalar failed");

        return result;
    }

    function leTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        bool result =  MpcCore.decrypt(MpcCore.le(castingValues.a8_s, castingValues.b8_s));
        leResult = result;
    
        // Calculate the results with cating to 16
        check16.res16_16 = MpcCore.le(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.le(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.le(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "leTest: cast 16 failed");

        // Calculate the result with cating to 32
        check32.res32_32 = MpcCore.le(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.le(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.le(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.le(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.le(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "leTest: cast 32 failed");

        // Calculate the result with cating to 64
        check64.res64_64 = MpcCore.le(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.le(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.le(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.le(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.le(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.le(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.le(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "leTest: cast 64 failed");

        // Calculate all available le functions for 128 bits
        check128.res128_128 =  MpcCore.le(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.le(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.le(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.le(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.le(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.le(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.le(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.le(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.le(castingValues.a128_s, castingValues.b64_s);
        bool res128 = decryptAndCompareResults128(check128);
        require(result == res128, "leTest: cast 128 failed");

        // Calculate all available le functions for 256 bits
        check256.res256_256 = MpcCore.le(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.le(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.le(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.le(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.le(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.le(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.le(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.le(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.le(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.le(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.le(castingValues.a256_s, castingValues.b128_s);
        bool res256 = decryptAndCompareResults256(check256);
        require(result == res256, "leTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.le(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.le(castingValues.a8_s, b)),
                "leTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.le(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.le(castingValues.a16_s, b)),
                "leTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.le(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.le(castingValues.a32_s, b)),
                "leTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.le(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.le(castingValues.a64_s, b)),
                "leTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.le(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.le(castingValues.a128_s, b)),
                "leTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.le(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.le(castingValues.a256_s, b)),
                "leTest: test 256 bits with scalar failed");

        return result;
    }
}