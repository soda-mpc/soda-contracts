// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract GetUserKeyContract {

    bytes keyShare0;
    bytes keyShare1;

    function getSavedUserKey() public view returns (bytes memory, bytes memory) {
        return (keyShare0, keyShare1);
    }

    
    function getUserKey(bytes calldata signedEK, bytes calldata signature) public returns (bytes memory, bytes memory) {

        (keyShare0, keyShare1) = MpcCore.getUserKey(signedEK, signature);
        return (keyShare0, keyShare1);
    }

}
