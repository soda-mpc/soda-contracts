// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract CheckTestnet {

    uint32 output = 3;

    function getOutput() public view returns (uint32) {
        return output;
    }

    function test() public {
        gtUint32 x = MpcCore.setPublic32(output);

        x = MpcCore.add(x, 10);
        output = MpcCore.decrypt(x);
    }

}