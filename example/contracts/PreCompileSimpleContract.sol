// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../lib/solidity/MpcCore.sol";

contract PreCompileSimpleContract {
    uint256 public storedData;
    gtUint8 public storedSecretData;
    gtUint8 public storedSecretData8;

    gtBool public storedSecretBool;

    function SetX(uint256 x) public {
        storedData = x;
    }

    function GetX() public view returns (uint256) {
        return storedData;
    }

    function GetSecretX() public view returns (gtUint8) {
        return storedSecretData;
    }

    function PrecompileCheck() public {

        gtUint8 a = MpcCore.setPublic8(uint8(5));
        gtUint8 c = MpcCore.add(a, uint8(5)); // 10
        gtUint8 max = MpcCore.max(c,a); // 10
        
        gtBool bit = MpcCore.ne(c,a);  // true
        storedSecretData = MpcCore.mux(bit,a,c); // 10

        storedSecretData = MpcCore.sub(storedSecretData,a); // 5

        ctUint8 cipher = MpcCore.offBoard(storedSecretData);
        storedSecretData = MpcCore.onBoard(cipher); // 5
        
        (c, a, storedSecretBool) = MpcCore.transfer(c, a, storedSecretData); // c = 5, a = 10

        bit = MpcCore.not(bit); // false
        bool val = MpcCore.decrypt(bit);
        if (val) {
            storedData = uint256(MpcCore.decrypt(a)); // 10
        } else {
            storedData = uint256(MpcCore.decrypt(c)); // 5
        }
    }
}
