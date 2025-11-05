// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesTransferAllowanceScalarTestsContract {

    struct AllGTCastingValues {
        gtUint8 a8_s;
        gtUint8 b8_s;
        gtUint16 a16_s;
        gtUint16 b16_s;
        gtUint32 a32_s;
        gtUint32 b32_s;
        gtUint64 a64_s;
        gtUint64 b64_s;
        gtUint128 a128_s;
        gtUint128 b128_s;
    }

    struct AllAllowanceValues {
        gtUint8 allowance8_s;
        gtUint16 allowance16_s;
        gtUint32 allowance32_s;
        gtUint64 allowance64_s;
        gtUint128 allowance128_s;
    }

    uint8 new_a;
    uint8 new_b;
    bool res;
    uint8 new_allowance;

    function getResults() public view returns (uint8, uint8, bool, uint8) {
        return (new_a, new_b, res, new_allowance);
    }

    function computeAndCheckTransfer16(AllGTCastingValues memory allGTCastingValues, AllAllowanceValues memory allAllowanceValues, uint8 amount) public {
        
        // Check all options for casting to 16 while amount is scalar and allowance is 8
        (gtUint16 newA_s, gtUint16 newB_s, gtBool res_s, gtUint16 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");


        // Check all options for casting to 16 while amount is scalar and allowance is 16
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    }

    function computeAndCheckTransfer32(AllGTCastingValues memory allGTCastingValues, AllAllowanceValues memory allAllowanceValues, uint8 amount) public {

        // Check all options for casting to 32 while amount is scalar and allowance is 8
        (gtUint32 newA_s, gtUint32 newB_s, gtBool res_s, gtUint32 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
    
        // Check all options for casting to 32 while amount is scalar and allowance is 16
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        // Check all options for casting to 32 while amount is scalar and allowance is 32
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    }

    function computeAndCheckTransfer64(AllGTCastingValues memory allGTCastingValues, AllAllowanceValues memory allAllowanceValues, uint8 amount) public {

        // Check all options for casting to 64 while amount is scalar and allowance is 8
        (gtUint64 newA_s, gtUint64 newB_s, gtBool res_s, gtUint64 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        // Check all options for casting to 64 while amount is scalar and allowance is 16
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        // Check all options for casting to 64 while amount is scalar and allowance is 32
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        // Check all options for casting to 64 while amount is scalar and allowance is 64
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
    
    }

    function computeAndCheckTransfer128(AllGTCastingValues memory allGTCastingValues, AllAllowanceValues memory allAllowanceValues, uint8 amount) public {

        // Check all options for casting to 128 while amount is scalar and allowance is 8
        (gtUint128 newA_s, gtUint128 newB_s, gtBool res_s, gtUint128 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        // Check all options for casting to 128 while amount is scalar and allowance is 16
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance16_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        // Check all options for casting to 128 while amount is scalar and allowance is 32
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance32_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        // Check all options for casting to 128 while amount is scalar and allowance is 64
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance64_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        // Check all options for casting to 128 while amount is scalar and allowance is 128
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, amount, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && new_allowance== MpcCore.decrypt(newAllowance_s), "transferWithAllowanceTest: check scalar failed");
    
    }

    function transferWithAllowanceTest(uint8 a, uint8 b, uint8 amount, uint8 allowance) public returns (uint8, uint8, bool, uint8) {
        AllGTCastingValues memory allGTCastingValues;
        AllAllowanceValues memory allAllowanceValues;
        allGTCastingValues.a8_s = MpcCore.setPublic8(a);
        allGTCastingValues.b8_s = MpcCore.setPublic8(b);
        allGTCastingValues.a16_s =  MpcCore.setPublic16(a);
        allGTCastingValues.b16_s =  MpcCore.setPublic16(b);
        allGTCastingValues.a32_s =  MpcCore.setPublic32(a);
        allGTCastingValues.b32_s =  MpcCore.setPublic32(b);
        allGTCastingValues.a64_s =  MpcCore.setPublic64(a);
        allGTCastingValues.b64_s =  MpcCore.setPublic64(b);
        allGTCastingValues.a128_s = MpcCore.setPublic128(a);
        allGTCastingValues.b128_s = MpcCore.setPublic128(b);
        allAllowanceValues.allowance8_s = MpcCore.setPublic8(allowance);
        allAllowanceValues.allowance16_s = MpcCore.setPublic16(allowance);
        allAllowanceValues.allowance32_s = MpcCore.setPublic32(allowance);
        allAllowanceValues.allowance64_s = MpcCore.setPublic64(allowance);
        allAllowanceValues.allowance128_s = MpcCore.setPublic128(allowance);
        
        // Calculate the expected result 
        (gtUint8 newA_s, gtUint8 newB_s, gtBool res_s, gtUint8 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance8_s);
        new_a =  MpcCore.decrypt(newA_s);
        new_b =  MpcCore.decrypt(newB_s);
        res =  MpcCore.decrypt(res_s);
        new_allowance =  MpcCore.decrypt(newAllowance_s);

        // Calculate the result with casting to 16
        computeAndCheckTransfer16(allGTCastingValues, allAllowanceValues, amount);

        // Calculate the result with casting to 32
        computeAndCheckTransfer32(allGTCastingValues, allAllowanceValues, amount);

        // Calculate the result with casting to 64
        computeAndCheckTransfer64(allGTCastingValues, allAllowanceValues, amount);

        // Calculate the result with casting to 128
        computeAndCheckTransfer128(allGTCastingValues, allAllowanceValues, amount);

        return (new_a, new_b, res, new_allowance); 
    }

}