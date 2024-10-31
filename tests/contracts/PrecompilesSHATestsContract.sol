// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesSHATestsContract {

    event SHAOutput(address indexed _owner, bytes _shaOutput);

    bytes shaOutput;

    function getSHAOutput() public view returns (bytes memory) {
        return shaOutput;
    }
   
    function sha256Fixed432BitInputTest(uint64 amount, uint64 seed1, uint64 seed2, address addr, uint64 padding1, uint16 padding2) public returns (bytes memory) {
            
        gtUint64 amountGT = MpcCore.setPublic64(amount);
        gtUint64 seed1GT = MpcCore.setPublic64(seed1);
        gtUint64 seed2GT = MpcCore.setPublic64(seed2);
        
        shaOutput = MpcCore.SHA256Fixed432BitInput(amountGT, seed1GT, seed2GT, addr, padding1, padding2);
        emit SHAOutput(msg.sender, shaOutput);

        return shaOutput;
    }
}