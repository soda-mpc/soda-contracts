// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract MalformedInputs {

    function setPublic8_return16(uint8 pt) internal returns (gtUint16) {
          return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            SetPublic(bytes1(uint8(MpcCore.MPC_TYPE.SUINT8_T)), uint256(pt)));
    }

    function setPublic16_return8(uint16 pt) internal returns (gtUint8) {
          return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            SetPublic(bytes1(uint8(MpcCore.MPC_TYPE.SUINT16_T)), uint256(pt)));
    }

    function decrypt(gtUint8 ct) internal returns (uint8){
          return uint8(ExtendedOperations(address(MPC_PRECOMPILE)).
            Decrypt(bytes1(uint8(MpcCore.MPC_TYPE.SUINT16_T)), gtUint8.unwrap(ct)));
    }

    function decrypt(gtUint16 ct) internal returns (uint16){
        return uint16(ExtendedOperations(address(MPC_PRECOMPILE)).
            Decrypt(bytes1(uint8(MpcCore.MPC_TYPE.SUINT16_T)), gtUint16.unwrap(ct)));
    }

    function malformedSmallInputDecrypt() public {
        uint16 a = 5;
        gtUint8 gtA = setPublic16_return8(a);
        uint8 res = MpcCore.decrypt(gtA);
    }

    function malformedLargeInputDecrypt() public {
        uint8 a = 5;
        gtUint16 gtA = setPublic8_return16(a);
        uint16 res = MpcCore.decrypt(gtA);
    }
}