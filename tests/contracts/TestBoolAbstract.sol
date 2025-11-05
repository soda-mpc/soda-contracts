// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

abstract contract TestBoolAbstract {

    struct AllGTCastingValues {
        gtUint8 a8_s;
        gtUint8 b8_s;
        gtUint16 a16_s;
        gtUint16 b16_s;
        gtUint32 a32_s;
        gtUint32 b32_s;
        gtUint64 a64_s;
        gtUint64 b64_s;
        gtUint128 a128_s;
        gtUint128 b128_s;
        gtUint256 a256_s;
        gtUint256 b256_s;
    }

    struct Check16 {
        gtBool res16_16;
        gtBool res8_16;
        gtBool res16_8;
    }

    struct Check32 {
        gtBool res32_32;
        gtBool res8_32;
        gtBool res32_8;
        gtBool res16_32;
        gtBool res32_16;
    }

    struct Check64 {
        gtBool res64_64;
        gtBool res8_64;
        gtBool res64_8;
        gtBool res16_64;
        gtBool res64_16;
        gtBool res32_64;
        gtBool res64_32;
    }

    struct Check128 {
        gtBool res128_128;
        gtBool res8_128;
        gtBool res128_8;
        gtBool res16_128;
        gtBool res128_16;
        gtBool res32_128;
        gtBool res128_32;
        gtBool res128_64;
        gtBool res64_128;
    }

    struct Check256 {
        gtBool res256_256;
        gtBool res8_256;
        gtBool res256_8;
        gtBool res16_256;
        gtBool res256_16;
        gtBool res32_256;
        gtBool res256_32;
        gtBool res256_64;
        gtBool res64_256;
        gtBool res256_128;
        gtBool res128_256;
    }

    function setPublicValues(AllGTCastingValues memory castingValues, uint8 a, uint8 b) public{
        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);
        castingValues.a16_s =  MpcCore.setPublic16(a);
        castingValues.b16_s =  MpcCore.setPublic16(b);
        castingValues.a32_s =  MpcCore.setPublic32(a);
        castingValues.b32_s =  MpcCore.setPublic32(b);
        castingValues.a64_s =  MpcCore.setPublic64(a);
        castingValues.b64_s =  MpcCore.setPublic64(b);
        castingValues.a128_s =  MpcCore.setPublic128(a);
        castingValues.b128_s =  MpcCore.setPublic128(b);
        castingValues.a256_s =  MpcCore.setPublic256(a);
        castingValues.b256_s =  MpcCore.setPublic256(b);
    }

    function decryptAndCompareResults16(Check16 memory check16) public returns (bool){

        // Calculate the result
        bool result = MpcCore.decrypt(check16.res16_16);

        require(result == MpcCore.decrypt(check16.res8_16) && result == MpcCore.decrypt(check16.res16_8), 
                                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults32(Check32 memory check32) public returns (bool){

        // Calculate the result
        bool result = MpcCore.decrypt(check32.res32_32);

        require(result == MpcCore.decrypt(check32.res8_32) && result == MpcCore.decrypt(check32.res32_8) 
                && result == MpcCore.decrypt(check32.res32_16) && result == MpcCore.decrypt(check32.res16_32), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults64(Check64 memory check64) public returns (bool){

        // Calculate the result
        bool result = MpcCore.decrypt(check64.res64_64);

        require(result == MpcCore.decrypt(check64.res8_64) && result == MpcCore.decrypt(check64.res64_8) 
                && result == MpcCore.decrypt(check64.res64_16) && result == MpcCore.decrypt(check64.res16_64)
                && result == MpcCore.decrypt(check64.res64_32) && result == MpcCore.decrypt(check64.res32_64), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults128(Check128 memory check128) public returns (bool){

        // Calculate the result
        bool result = MpcCore.decrypt(check128.res128_128);

        require(result == MpcCore.decrypt(check128.res8_128) && result == MpcCore.decrypt(check128.res128_8) 
                && result == MpcCore.decrypt(check128.res16_128) && result == MpcCore.decrypt(check128.res128_16)
                && result == MpcCore.decrypt(check128.res32_128) && result == MpcCore.decrypt(check128.res128_32)
                && result == MpcCore.decrypt(check128.res128_64) && result == MpcCore.decrypt(check128.res64_128), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults256(Check256 memory check256) public returns (bool){

        bool result = MpcCore.decrypt(check256.res256_256);

        require(result == MpcCore.decrypt(check256.res8_256) && result == MpcCore.decrypt(check256.res256_8) 
                && result == MpcCore.decrypt(check256.res16_256) && result == MpcCore.decrypt(check256.res256_16)
                && result == MpcCore.decrypt(check256.res32_256) && result == MpcCore.decrypt(check256.res256_32)
                && result == MpcCore.decrypt(check256.res256_64) && result == MpcCore.decrypt(check256.res64_256)
                && result == MpcCore.decrypt(check256.res256_128) && result == MpcCore.decrypt(check256.res128_256), 
                "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }
}