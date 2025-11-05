// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestAbstract.sol";

contract PrecompilesMiscellaneousTestsContract is TestAbstract {

    uint8 divResult;
    uint8 remResult;
    uint8 muxResult;
    bool boolResult;

    function getDivResult() public view returns (uint8) {
        return divResult;
    }
    function getRemResult() public view returns (uint8) {
        return remResult;
    }
    function getMuxResult() public view returns (uint8) {
        return muxResult;
    }
    
    function getBoolResult() public view returns (bool) {
        return boolResult;
    }

    function divTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.div(castingValues.a8_s, castingValues.b8_s));
        divResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.div(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.div(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.div(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "divTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.div(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.div(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.div(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.div(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.div(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "divTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.div(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.div(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.div(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.div(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.div(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.div(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.div(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "divTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.div(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.div(castingValues.a8_s, b)),
                "divTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.div(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.div(castingValues.a16_s, b)),
                "divTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.div(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.div(castingValues.a32_s, b)),
                "divTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.div(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.div(castingValues.a64_s, b)),
                "divTest: test 64 bits with scalar failed");

        return result;
    }

    function remTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.rem(castingValues.a8_s, castingValues.b8_s));
        remResult = result;

        // Calculate the results with casting to 16
        check16.res16_16 = MpcCore.rem(castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.rem(castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.rem(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "remTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.rem(castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.rem(castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.rem(castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.rem(castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.rem(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "remTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.rem(castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.rem(castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.rem(castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.rem(castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.rem(castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.rem(castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.rem(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "remTest: cast 64 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.rem(a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.rem(castingValues.a8_s, b)),
                "remTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.rem(a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.rem(castingValues.a16_s, b)),
                "remTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.rem(a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.rem(castingValues.a32_s, b)),
                "remTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.rem(a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.rem(castingValues.a64_s, b)),
                "remTest: test 64 bits with scalar failed");

        return result;
    }

    function muxTest(bool selectionBit, uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        gtBool selectionBit_s = MpcCore.setPublic(selectionBit);
        
        // Calculate the expected result 
        uint8 result =  MpcCore.decrypt(MpcCore.mux(selectionBit_s, castingValues.a8_s, castingValues.b8_s));
        muxResult = result;

        // Calculate the result with casting to 16
        check16.res16_16 = MpcCore.mux(selectionBit_s, castingValues.a16_s, castingValues.b16_s);
        check16.res8_16 = MpcCore.mux(selectionBit_s, castingValues.a8_s, castingValues.b16_s);
        check16.res16_8 = MpcCore.mux(selectionBit_s, castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "muxTest: cast 16 failed");

        // Calculate the result with casting to 32
        check32.res32_32 = MpcCore.mux(selectionBit_s, castingValues.a32_s, castingValues.b32_s);
        check32.res8_32 = MpcCore.mux(selectionBit_s, castingValues.a8_s, castingValues.b32_s);
        check32.res32_8 = MpcCore.mux(selectionBit_s, castingValues.a32_s, castingValues.b8_s);
        check32.res16_32 = MpcCore.mux(selectionBit_s, castingValues.a16_s, castingValues.b32_s);
        check32.res32_16 = MpcCore.mux(selectionBit_s, castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "muxTest: cast 32 failed");

        // Calculate the result with casting to 64
        check64.res64_64 = MpcCore.mux(selectionBit_s, castingValues.a64_s, castingValues.b64_s);
        check64.res8_64 = MpcCore.mux(selectionBit_s, castingValues.a8_s, castingValues.b64_s);
        check64.res64_8 = MpcCore.mux(selectionBit_s, castingValues.a64_s, castingValues.b8_s);
        check64.res16_64 = MpcCore.mux(selectionBit_s, castingValues.a16_s, castingValues.b64_s);
        check64.res64_16 = MpcCore.mux(selectionBit_s, castingValues.a64_s, castingValues.b16_s);
        check64.res32_64 = MpcCore.mux(selectionBit_s, castingValues.a32_s, castingValues.b64_s);
        check64.res64_32 = MpcCore.mux(selectionBit_s, castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "muxTest: cast 64 failed");

        // Calculate all available mux functions for 128 bits
        check128.res128_128 =  MpcCore.mux(selectionBit_s, castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.mux(selectionBit_s, castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.mux(selectionBit_s, castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.mux(selectionBit_s, castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.mux(selectionBit_s, castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.mux(selectionBit_s, castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.mux(selectionBit_s, castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.mux(selectionBit_s, castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.mux(selectionBit_s, castingValues.a128_s, castingValues.b64_s);
        uint128 res128 = decryptAndCompareResults128(check128);
        require(result == res128, "muxTest: cast 128 failed");

        // Calculate all available mux functions for 256 bits
        check256.res256_256 = MpcCore.mux(selectionBit_s, castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.mux(selectionBit_s, castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.mux(selectionBit_s, castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.mux(selectionBit_s, castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.mux(selectionBit_s, castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.mux(selectionBit_s, castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.mux(selectionBit_s, castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.mux(selectionBit_s, castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.mux(selectionBit_s, castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.mux(selectionBit_s, castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.mux(selectionBit_s, castingValues.a256_s, castingValues.b128_s);
        uint256 res256 = decryptAndCompareResults256(check256);
        require(result == res256, "muxTest: cast 256 failed");

        // Check the result with scalar
        require(result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, a, castingValues.b8_s)) && result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, castingValues.a8_s, b)),
                "muxTest: test 8 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, a, castingValues.b16_s)) && result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, castingValues.a16_s, b)),
                "muxTest: test 16 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, a, castingValues.b32_s)) && result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, castingValues.a32_s, b)),
                "muxTest: test 32 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, a, castingValues.b64_s)) && result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, castingValues.a64_s, b)),
                "muxTest: test 64 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, a, castingValues.b128_s)) && result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, castingValues.a128_s, b)),
                "muxTest: test 128 bits with scalar failed");
        require(result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, a, castingValues.b256_s)) && result == MpcCore.decrypt(MpcCore.mux(selectionBit_s, castingValues.a256_s, b)),
                "muxTest: test 256 bits with scalar failed");

        return result; 
    }

    function notTest(bool a) public returns (bool) {
        gtBool a_s = MpcCore.setPublic(a);
        gtBool not = MpcCore.not(a_s);
        boolResult = MpcCore.decrypt(not); 

        return boolResult;
    }

}