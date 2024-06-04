// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract GetUserKeyContract {

    event UserKey(address indexed _owner, bytes _keyShare0, bytes _keyShare1);
    event DeleteKey(address indexed _owner);

    function getUserKey(bytes calldata signedEK, bytes calldata signature) public returns (bytes memory, bytes memory) {
        bytes memory keyShare0;
        bytes memory keyShare1;

        (keyShare0, keyShare1) = MpcCore.getUserKey(signedEK, signature);
        emit UserKey(msg.sender, keyShare0, keyShare1);
        return (keyShare0, keyShare1);
    }

    function deleteUserKey(bytes calldata signature) public {
        MpcCore.deleteUserKey(signature);
        emit DeleteKey(msg.sender);
    }

}
