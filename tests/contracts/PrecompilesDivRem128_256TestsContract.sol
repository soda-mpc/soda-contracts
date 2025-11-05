// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestAbstract.sol";

contract PrecompilesDivRem128_256TestsContract is TestAbstract {

    uint128 divResult;
    uint128 remResult;

    function getDivResult() public view returns (uint128) {
        return divResult;
    }

    function getRemResult() public view returns (uint128) {
        return remResult;
    }

    function divTest(uint8 a, uint8 b) public  {
        AllGTCastingValues memory castingValues;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate all available div functions for 128 bits
        check128.res128_128 =  MpcCore.div(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.div(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.div(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.div(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.div(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.div(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.div(castingValues.a128_s, castingValues.b32_s);
        check128.res128_64 = MpcCore.div(castingValues.a64_s, castingValues.b128_s);
        check128.res64_128 = MpcCore.div(castingValues.a128_s, castingValues.b64_s);
        uint128 result128 = decryptAndCompareResults128(check128);

        // Calculate all available div functions for 256 bits
        check256.res256_256 = MpcCore.div(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.div(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.div(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.div(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.div(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.div(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.div(castingValues.a256_s, castingValues.b32_s);
        check256.res256_64 = MpcCore.div(castingValues.a64_s, castingValues.b256_s);
        check256.res64_256 = MpcCore.div(castingValues.a256_s, castingValues.b64_s);
        check256.res256_128 = MpcCore.div(castingValues.a128_s, castingValues.b256_s);
        check256.res128_256 = MpcCore.div(castingValues.a256_s, castingValues.b128_s);
        uint256 result256 = decryptAndCompareResults256(check256);

        require(result128 == result256, "divTest: test 128 bits and 256 bits failed");
        divResult = result128;

        // Check the result with scalar
        require(result128 == MpcCore.decrypt(MpcCore.div(a, castingValues.b128_s)) && result128 == MpcCore.decrypt(MpcCore.div(castingValues.a128_s, b)),
                "divTest: test 128 bits with scalar failed");
        require(result256 == MpcCore.decrypt(MpcCore.div(a, castingValues.b256_s)) && result256 == MpcCore.decrypt(MpcCore.div(castingValues.a256_s, b)),
                "divTest: test 256 bits with scalar failed");
    }

    function remTest(uint8 a, uint8 b) public  {
        AllGTCastingValues memory castingValues;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate all available rem functions for 128 bits
        check128.res128_128 =  MpcCore.rem(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.rem(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.rem(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.rem(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.rem(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.rem(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.rem(castingValues.a128_s, castingValues.b32_s);
        check128.res128_64 = MpcCore.rem(castingValues.a64_s, castingValues.b128_s);
        check128.res64_128 = MpcCore.rem(castingValues.a128_s, castingValues.b64_s);
        uint128 result128 = decryptAndCompareResults128(check128);

        // Calculate all available rem functions for 256 bits
        check256.res256_256 = MpcCore.rem(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.rem(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.rem(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.rem(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.rem(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.rem(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.rem(castingValues.a256_s, castingValues.b32_s);
        check256.res256_64 = MpcCore.rem(castingValues.a64_s, castingValues.b256_s);
        check256.res64_256 = MpcCore.rem(castingValues.a256_s, castingValues.b64_s);
        check256.res256_128 = MpcCore.rem(castingValues.a128_s, castingValues.b256_s);
        check256.res128_256 = MpcCore.rem(castingValues.a256_s, castingValues.b128_s);
        uint256 result256 = decryptAndCompareResults256(check256);

        require(result128 == result256, "remTest: test 128 bits and 256 bits failed");
        remResult = result128;

        // Check the result with scalar
        require(result128 == MpcCore.decrypt(MpcCore.rem(a, castingValues.b128_s)) && result128 == MpcCore.decrypt(MpcCore.rem(castingValues.a128_s, b)),
                "remTest: test 128 bits with scalar failed");
        require(result256 == MpcCore.decrypt(MpcCore.rem(a, castingValues.b256_s)) && result256 == MpcCore.decrypt(MpcCore.rem(castingValues.a256_s, b)),
                "remTest: test 256 bits with scalar failed");
    }

    
}