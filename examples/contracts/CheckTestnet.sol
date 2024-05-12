// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract CheckTestnet {

    uint32 output = 3;
    uint64 outputMult = 3;
    bool ok;
    ctUint32 userCt = ctUint32.wrap(0);

    function getBoolOutput() public view returns (bool){
        return ok;
    }

    function getOutput() public view returns (uint32) {
        return output;
    }

    function getOutputMult() public view returns (uint64) {
        return outputMult;
    }

    function getUserCt() public view returns (ctUint32) {
        return userCt;
    }

    function test(address addr) public {
        gtUint32 x = MpcCore.setPublic32(10); // x = 10
        gtUint32 y = MpcCore.setPublic32(3);  // y = 3
        gtBool gtok = MpcCore.setPublic(true); // gtok = true

        ok = MpcCore.decrypt(gtok);
        ok = MpcCore.decrypt(MpcCore.not(gtok)); // ok = false


        x = MpcCore.add(x, 10); // x = 20
        
        gtUint32 a;
        gtUint32 b;
        (a, b, gtok) = MpcCore.transfer(x, y, y); // (a, b, gtok) = (17, 6, true)

        b = MpcCore.sub(b, 1); // b = 5
        outputMult = MpcCore.decrypt(MpcCore.mul(b, 2)); // outputMult = 10
        b = MpcCore.div(10, b); // b = 2
        b = MpcCore.rem(3, b); // b = 1

        b = MpcCore.and(b, 4); // b = 0
        b = MpcCore.or(b, 34); // b = 34
        b = MpcCore.xor(b, 2); // b = 32
        b = MpcCore.min(b, 16); // b = 16
        b = MpcCore.max(20, b); // b = 20

        ctUint32 ct = MpcCore.offBoard(b);
        a = MpcCore.onBoard(ct); // a = 20

        a = MpcCore.checkedAdd(a, b); // a = 40


        gtok = MpcCore.eq(b , 20); // gtok = true
        gtok = MpcCore.ne(b , 20); // gtok = false
        gtok = MpcCore.ge(b , 20); // gtok = true
        gtok = MpcCore.gt(b , 20); // gtok = false
        gtok = MpcCore.le(b , 20); // gtok = true
        gtok = MpcCore.lt(b , 20); // gtok = false

        userCt = MpcCore.offBoardToUser(b, addr);

        output = MpcCore.decrypt(a);
        
        ok = MpcCore.decrypt(gtok);
    }

}