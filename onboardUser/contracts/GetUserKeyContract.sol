// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./MpcCore.sol";

contract GetUserKeyContract {

    bytes userKey;

    function getSavedUserKey() public view returns (bytes memory) {
        return userKey;
    }

    
    function getUserKey(bytes calldata signedEK, bytes calldata signature) public returns (bytes memory) {

        userKey = MpcCore.getUserKey(signedEK, signature);
        return userKey;
    }

}
