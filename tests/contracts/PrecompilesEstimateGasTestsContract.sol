// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesEstimateGasTestsContract {

    /*
    * This function contains all available precompiles functions.
    * The function is used to check that the estimate gas mechanism works correctly on all precompiles functions.
    */
    function estimateGasTest() public returns (uint8) {
        gtUint8 a = MpcCore.setPublic8(10); // a = 10
        ctUint8 cipher = MpcCore.offBoard(a);
        gtUint8 b = MpcCore.onBoard(cipher); // b = 10
        b = MpcCore.add(b, b); // b = 20
        b = MpcCore.sub(b, a); // b = 10
        gtUint16 bMult = MpcCore.mul(b, b); // bMult = 100
        b = MpcCore.div(b, a); // b = 1
        b = MpcCore.rem(b, a); // b = 0
        gtBool res = MpcCore.lt(b, a);  // res = 1
        res = MpcCore.gt(b, a);  // res = 0
        res = MpcCore.le(b, a);  // res = 1
        res = MpcCore.ge(b, a);  // res = 0
        res = MpcCore.eq(b, a);  // res = 0
        b = MpcCore.and(b, a);   // b = 0
        b = MpcCore.or(b, a);    // b = 10
        b = MpcCore.xor(b, a);   // b = 0
        res = MpcCore.not(res);  // res = 1
        res = MpcCore.ne(b, a);  // res = 1
        b = MpcCore.shl(b, a);   // b = 0
        b = MpcCore.shr(b, a);   // b = 0
        b = MpcCore.max(b, a);   // b = 10
        b = MpcCore.min(b, a);   // b = 0
        b = MpcCore.mux(res, b, a); // b = 0
        (a, b, res) = MpcCore.transfer(a, b, 5); // a = 5, b = 5, res = 1
        uint8 clear = MpcCore.decrypt(a);
        return clear;
    }

    
}