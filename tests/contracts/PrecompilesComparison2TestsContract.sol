// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestBoolAbstract.sol";

contract PrecompilesComparison2TestsContract is TestBoolAbstract {

    bool eqResult;
    bool neResult;
    
    function getEqResult() public view returns (bool) {
        return eqResult;
    }

    function getNeResult() public view returns (bool) {
        return neResult;
    }

    function eqTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        bool result =  MpcCore.decrypt(MpcCore.eq(castingValues.a8_s, castingValues.b8_s));
        eqResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.eq(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.eq(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.eq(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "eqTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.eq(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.eq(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.eq(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.eq(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.eq(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "eqTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.eq(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.eq(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.eq(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.eq(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.eq(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.eq(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.eq(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "eqTest: cast 64 failed");

        // Calculate all available eq functions for 128 bits
        check128.res128_128 =  MpcCore.eq(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.eq(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.eq(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.eq(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.eq(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.eq(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.eq(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.eq(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.eq(castingValues.a128_s, castingValues.b64_s);
        bool res128 = decryptAndCompareResults128(check128);
        require(result == res128, "eqTest: cast 128 failed");

        // Calculate all available eq functions for 256 bits
        check256.res256_256 = MpcCore.eq(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.eq(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.eq(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.eq(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.eq(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.eq(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.eq(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.eq(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.eq(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.eq(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.eq(castingValues.a256_s, castingValues.b128_s);
        bool res256 = decryptAndCompareResults256(check256);
        require(result == res256, "eqTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a8_s, b)),
                "eqTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a16_s, b)),
                "eqTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a32_s, b)),
                "eqTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a64_s, b)),
                "eqTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a128_s, b)),
                "eqTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.eq(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.eq(castingValues.a256_s, b)),
                "eqTest: test 256 bits with scalar failed");    

        return result;
    }

    function neTest(uint8 a, uint8 b) public returns (bool) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        bool result =  MpcCore.decrypt(MpcCore.ne(castingValues.a8_s, castingValues.b8_s));
        neResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.ne(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.ne(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.ne(castingValues.a16_s, castingValues.b8_s);
        bool res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "neTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.ne(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.ne(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.ne(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.ne(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.ne(castingValues.a32_s, castingValues.b16_s);
        bool res32 = decryptAndCompareResults32(check32);
        require(result == res32, "neTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.ne(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.ne(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.ne(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.ne(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.ne(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.ne(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.ne(castingValues.a64_s, castingValues.b32_s);
        bool res64 = decryptAndCompareResults64(check64);
        require(result == res64, "neTest: cast 64 failed");

        // Calculate all available ne functions for 128 bits
        check128.res128_128 =  MpcCore.ne(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.ne(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.ne(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.ne(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.ne(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.ne(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.ne(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.ne(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.ne(castingValues.a128_s, castingValues.b64_s);
        bool res128 = decryptAndCompareResults128(check128);
        require(result == res128, "neTest: cast 128 failed");

        // Calculate all available ne functions for 256 bits
        check256.res256_256 = MpcCore.ne(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.ne(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.ne(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.ne(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.ne(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.ne(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.ne(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.ne(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.ne(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.ne(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.ne(castingValues.a256_s, castingValues.b128_s);
        bool res256 = decryptAndCompareResults256(check256);
        require(result == res256, "neTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a8_s, b)),
                "neTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a16_s, b)),
                "neTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a32_s, b)),
                "neTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a64_s, b)),
                "neTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a128_s, b)),
                "neTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.ne(a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.ne(castingValues.a256_s, b)),
                "neTest: test 256 bits with scalar failed");

        return result;
    }
}