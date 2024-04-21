// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract CheckTestnet {

    uint32 output = 3;
    bool ok;

    function getBoolOutput() public view returns (bool){
        return ok;
    }

    function getOutput() public view returns (uint32) {
        return output;
    }

    function test() public {
        gtUint32 x = MpcCore.setPublic32(10);
        gtUint32 y = MpcCore.setPublic32(3);
        gtBool gtok = MpcCore.setPublic(true);
        ok = MpcCore.decrypt(MpcCore.not(gtok));


        x = MpcCore.add(x, 10);
        output = MpcCore.decrypt(x);

        gtUint32 a;
        gtUint32 b;
        (a, b, gtok) = MpcCore.transfer(x, y, y);
        output = MpcCore.decrypt(b);
    }

}