// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";


contract PrecompilesShiftTestsContract {

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

    uint8 result;
    uint8 result8;
    uint16 result16;
    uint32 result32;
    uint64 result64;
    uint128 result128;
    uint256 result256;

    function getResult() public view returns (uint8) {
        return result;
    }

    function getAllShiftResults() public view returns (uint8, uint16, uint32, uint64, uint128, uint256) { 
        return (result8, result16, result32, result64, result128, result256);
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

    function shlTest(uint8 a, uint8 b) public returns (uint8, uint16, uint32, uint64, uint128, uint256) {
        AllGTCastingValues memory castingValues;
        setPublicValues(castingValues, a, b);
        
        result8 = MpcCore.decrypt(MpcCore.shl(castingValues.a8_s, b));
        result16 = MpcCore.decrypt(MpcCore.shl(castingValues.a16_s, b));
        result32 = MpcCore.decrypt(MpcCore.shl(castingValues.a32_s, b));
        result64 = MpcCore.decrypt(MpcCore.shl(castingValues.a64_s, b));
        result128 = MpcCore.decrypt(MpcCore.shl(castingValues.a128_s, b));
        result256 = MpcCore.decrypt(MpcCore.shl(castingValues.a256_s, b));

        return (result8, result16, result32, result64, result128, result256); 
    } 

    function shrTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        setPublicValues(castingValues, a, b);
        
        result = MpcCore.decrypt(MpcCore.shr(castingValues.a8_s, b));
        require(result == MpcCore.decrypt(MpcCore.shr(castingValues.a16_s, b)) && result == MpcCore.decrypt(MpcCore.shr(castingValues.a32_s, b))
                && result == MpcCore.decrypt(MpcCore.shr(castingValues.a64_s, b)) && result == MpcCore.decrypt(MpcCore.shr(castingValues.a128_s, b))
                && result == MpcCore.decrypt(MpcCore.shr(castingValues.a256_s, b)), 
                "shrTest failed");
        return result; 
    } 

}