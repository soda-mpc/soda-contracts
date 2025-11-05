// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestBoolAbstract.sol";

contract PrecompilesComparison3TestsContract is TestBoolAbstract {

    bool geResult;
    bool ltResult;

   function getGeResult() public view returns (bool) {
        return geResult;
    }

    function getLtResult() public view returns (bool) {
        return ltResult;
    }

    function geTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        bool result =  MpcCore.decrypt(MpcCore.ge(castingValues.a8_s, castingValues.b8_s));
        geResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.ge(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.ge(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.ge(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "geTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.ge(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.ge(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.ge(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.ge(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.ge(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "geTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.ge(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.ge(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.ge(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.ge(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.ge(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.ge(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.ge(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "geTest: cast 64 failed");

        // Calculate all available ge functions for 128 bits
        check128.res128_128 =  MpcCore.ge(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.ge(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.ge(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.ge(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.ge(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.ge(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.ge(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.ge(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.ge(castingValues.a128_s, castingValues.b64_s);
        bool res128 = decryptAndCompareResults128(check128);
        require(result == res128, "geTest: cast 128 failed");

        // Calculate all available ge functions for 256 bits
        check256.res256_256 = MpcCore.ge(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.ge(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.ge(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.ge(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.ge(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.ge(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.ge(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.ge(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.ge(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.ge(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.ge(castingValues.a256_s, castingValues.b128_s);
        bool res256 = decryptAndCompareResults256(check256);
        require(result == res256, "geTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a8_s, b)),
                "geTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a16_s, b)),
                "geTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a32_s, b)),
                "geTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a64_s, b)),
                "geTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a128_s, b)),
                "geTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ge(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.ge(castingValues.a256_s, b)),
                "geTest: test 256 bits with scalar failed");

        return result;
    }

    function ltTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        bool result =  MpcCore.decrypt(MpcCore.lt(castingValues.a8_s, castingValues.b8_s));
        ltResult = result;

        // Calculate the results with cating to 16
        check16.res16_16 = MpcCore.lt(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.lt(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.lt(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "letTest: cast 16 failed");

        // Calculate the result with cating to 32
        check32.res32_32 = MpcCore.lt(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.lt(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.lt(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.lt(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.lt(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "letTest: cast 32 failed");

        // Calculate the result with cating to 64
        check64.res64_64 = MpcCore.lt(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.lt(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.lt(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.lt(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.lt(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.lt(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.lt(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "letTest: cast 64 failed");

        // Calculate all available lt functions for 128 bits
        check128.res128_128 =  MpcCore.lt(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.lt(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.lt(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.lt(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.lt(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.lt(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.lt(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.lt(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.lt(castingValues.a128_s, castingValues.b64_s);
        bool res128 = decryptAndCompareResults128(check128);
        require(result == res128, "ltTest: cast 128 failed");

        // Calculate all available lt functions for 256 bits
        check256.res256_256 = MpcCore.lt(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.lt(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.lt(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.lt(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.lt(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.lt(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.lt(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.lt(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.lt(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.lt(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.lt(castingValues.a256_s, castingValues.b128_s);
        bool res256 = decryptAndCompareResults256(check256);
        require(result == res256, "ltTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.lt(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.lt(castingValues.a8_s, b)),
                "letTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.lt(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.lt(castingValues.a16_s, b)),
                "letTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.lt(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.lt(castingValues.a32_s, b)),
                "letTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.lt(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.lt(castingValues.a64_s, b)),
                "letTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.lt(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.lt(castingValues.a128_s, b)),
                "letTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.lt(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.lt(castingValues.a256_s, b)),
                "letTest: test 256 bits with scalar failed");

        return result;
    }

}