// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";
import "./TestAbstract.sol";

contract PrecompilesMul128_256TestsContract is TestAbstract {

    uint128 mulResult;
    uint128 checkedMulResult;

    function getMulResult() public view returns (uint128) {
        return mulResult;
    }

    function getCheckedMulResult() public view returns (uint128) {
        return checkedMulResult;
    }

    function mulTest(uint8 a, uint8 b) public  {
        AllGTCastingValues memory castingValues;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate all available mul functions for 128 bits
        check128.res128_128 =  MpcCore.mul(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.mul(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.mul(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.mul(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.mul(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.mul(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.mul(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.mul(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.mul(castingValues.a128_s, castingValues.b64_s);
        uint128 result128 = decryptAndCompareResults128(check128);

        // Calculate all available mul functions for 256 bits
        check256.res256_256 = MpcCore.mul(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.mul(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.mul(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.mul(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.mul(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.mul(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.mul(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.mul(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.mul(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.mul(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.mul(castingValues.a256_s, castingValues.b128_s);
        uint256 result256 = decryptAndCompareResults256(check256);

        require(result128 == result256, "mulTest: test 128 bits and 256 bits failed");
        mulResult = result128;

        // Check the result with scalar
        require(result128 == MpcCore.decrypt(MpcCore.mul(a, castingValues.b128_s)) && result128 == MpcCore.decrypt(MpcCore.mul(castingValues.a128_s, b)),
                "mulTest: test 8 bits with scalar failed");
        require(result256 == MpcCore.decrypt(MpcCore.mul(a, castingValues.b256_s)) && result256 == MpcCore.decrypt(MpcCore.mul(castingValues.a256_s, b)),
                "mulTest: test 256 bits with scalar failed");
    }

    function checkedMulTest(uint8 a, uint8 b) public  {
        AllGTCastingValues memory castingValues;
        Check128 memory check128;
        Check256 memory check256;
        setPublicValues(castingValues, a, b);
        
        // Calculate all available mul functions for 128 bits
        check128.res128_128 =  MpcCore.checkedMul(castingValues.a128_s, castingValues.b128_s);
        check128.res8_128 = MpcCore.checkedMul(castingValues.a8_s, castingValues.b128_s);
        check128.res128_8 = MpcCore.checkedMul(castingValues.a128_s, castingValues.b8_s);
        check128.res16_128 = MpcCore.checkedMul(castingValues.a16_s, castingValues.b128_s);
        check128.res128_16 = MpcCore.checkedMul(castingValues.a128_s, castingValues.b16_s);
        check128.res32_128 = MpcCore.checkedMul(castingValues.a32_s, castingValues.b128_s);
        check128.res128_32 = MpcCore.checkedMul(castingValues.a128_s, castingValues.b32_s);
        check128.res64_128 = MpcCore.checkedMul(castingValues.a64_s, castingValues.b128_s);
        check128.res128_64 = MpcCore.checkedMul(castingValues.a128_s, castingValues.b64_s);
        uint128 result128 = decryptAndCompareResults128(check128);

        // Calculate all available checkedMul functions for 256 bits
        check256.res256_256 = MpcCore.checkedMul(castingValues.a256_s, castingValues.b256_s);
        check256.res8_256 = MpcCore.checkedMul(castingValues.a8_s, castingValues.b256_s);
        check256.res256_8 = MpcCore.checkedMul(castingValues.a256_s, castingValues.b8_s);
        check256.res16_256 = MpcCore.checkedMul(castingValues.a16_s, castingValues.b256_s);
        check256.res256_16 = MpcCore.checkedMul(castingValues.a256_s, castingValues.b16_s);
        check256.res32_256 = MpcCore.checkedMul(castingValues.a32_s, castingValues.b256_s);
        check256.res256_32 = MpcCore.checkedMul(castingValues.a256_s, castingValues.b32_s);
        check256.res64_256 = MpcCore.checkedMul(castingValues.a64_s, castingValues.b256_s);
        check256.res256_64 = MpcCore.checkedMul(castingValues.a256_s, castingValues.b64_s);
        check256.res128_256 = MpcCore.checkedMul(castingValues.a128_s, castingValues.b256_s);
        check256.res256_128 = MpcCore.checkedMul(castingValues.a256_s, castingValues.b128_s);
        uint256 result256 = decryptAndCompareResults256(check256);
        require(result128 == result256, "checkedMulTest: test 128 bits and 256 bits failed");
        checkedMulResult = result128;

        // Check the result with scalar
        require(result128 == MpcCore.decrypt(MpcCore.checkedMul(a, castingValues.b128_s)) && result128 == MpcCore.decrypt(MpcCore.checkedMul(castingValues.a128_s, b)),
                "checkedMulTest: test 8 bits with scalar failed");
        require(result256 == MpcCore.decrypt(MpcCore.checkedMul(a, castingValues.b256_s)) && result256 == MpcCore.decrypt(MpcCore.checkedMul(castingValues.a256_s, b)),
                "checkedMulTest: test 256 bits with scalar failed");
    }

    
}