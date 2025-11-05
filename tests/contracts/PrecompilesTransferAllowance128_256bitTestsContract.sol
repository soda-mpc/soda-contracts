// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesTransferAllowance128_256bitTestsContract {

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
        gtUint256 a256_s;
        gtUint256 b256_s;
    }

    struct AllAmountValues {
        gtUint8 amount8_s;
        gtUint16 amount16_s;
        gtUint32 amount32_s;
        gtUint64 amount64_s;
        gtUint128 amount128_s;
        gtUint256 amount256_s;
        uint8 amount;
    }

    struct AllAllowanceValues {
        gtUint8 allowance8_s;
        gtUint16 allowance16_s;
        gtUint32 allowance32_s;
        gtUint64 allowance64_s;
        gtUint128 allowance128_s;
        gtUint256 allowance256_s;
    }

    uint8 newA;
    uint8 newB;
    bool result;
    uint8 newAllowance;

    function getResults() public view returns (uint8, uint8, bool, uint8) {
        return (newA, newB, result, newAllowance);
    }

    function computeAndCheckTransfer128(AllGTCastingValues memory allGTCastingValues, AllAmountValues memory allAmountValues, AllAllowanceValues memory allAllowanceValues, uint8 new_a, uint8 new_b, bool res, uint8 newAllowance) public {

        // Check all options for casting to 128 while amount is 128 and allowance is 128
        (gtUint128 newA_s, gtUint128 newB_s, gtBool res_s, gtUint128 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, allAmountValues.amount128_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // // Check all options for casting to 128 while amount is 64 and allowance is 128
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 128 while amount is 32 and allowance is 128
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, allAmountValues.amount32_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 128 while amount is 16 and allowance is 128
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, allAmountValues.amount16_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 128 while amount is 8 and allowance is 128
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, allAmountValues.amount8_s, allAllowanceValues.allowance128_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 128 while amount is 8 and allowance is 8
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b8_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b16_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b32_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b64_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

    }

    function computeAndCheckTransfer256(AllGTCastingValues memory allGTCastingValues, AllAmountValues memory allAmountValues, AllAllowanceValues memory allAllowanceValues, uint8 new_a, uint8 new_b, bool res, uint8 newAllowance) public {

        // Check all options for casting to 256 while amount is 256 and allowance is 256
        (gtUint256 newA_s, gtUint256 newB_s, gtBool res_s, gtUint256 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b256_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b256_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b8_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b256_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b16_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b256_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b32_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b256_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b64_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b256_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b128_s, allAmountValues.amount256_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 256 while amount is 128 and allowance is 256
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b256_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b256_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b8_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b256_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b16_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b256_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b32_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b256_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b64_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b256_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b128_s, allAmountValues.amount128_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 256 while amount is 64 and allowance is 256
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b256_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b256_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b8_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b256_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b16_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b256_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b32_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b256_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b256_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b128_s, allAmountValues.amount64_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 256 while amount is 32 and allowance is 256
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b256_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b256_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b8_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b256_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b16_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b256_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b256_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b64_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b256_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b128_s, allAmountValues.amount32_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 256 while amount is 16 and allowance is 256
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b256_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b256_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b8_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b256_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b16_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b256_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b32_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b256_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b64_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b256_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b128_s, allAmountValues.amount16_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        // Check all options for casting to 256 while amount is 8 and allowance is 256
        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b256_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b256_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b8_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b256_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b16_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 64 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b256_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b32_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b256_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b64_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a128_s, allGTCastingValues.b256_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a256_s, allGTCastingValues.b128_s, allAmountValues.amount8_s, allAllowanceValues.allowance256_s);
        require(new_a == MpcCore.decrypt(newA_s) && new_b == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s), "transferTest: cast 128 failed");

    }


    function transferWithAllowanceTest(uint8 a, uint8 b, uint8 amount, uint8 allowance) public returns (uint8, uint8, bool, uint8) {
        AllGTCastingValues memory allGTCastingValues;
        AllAmountValues memory allAmountValues;
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
        allGTCastingValues.a256_s = MpcCore.setPublic256(a);
        allGTCastingValues.b256_s = MpcCore.setPublic256(b);
        allAmountValues.amount8_s = MpcCore.setPublic8(amount);
        allAmountValues.amount16_s = MpcCore.setPublic16(amount);
        allAmountValues.amount32_s = MpcCore.setPublic32(amount);
        allAmountValues.amount64_s = MpcCore.setPublic64(amount);
        allAmountValues.amount128_s = MpcCore.setPublic128(amount);
        allAmountValues.amount256_s = MpcCore.setPublic256(amount);
        allAmountValues.amount = amount;
        allAllowanceValues.allowance8_s = MpcCore.setPublic8(allowance);
        allAllowanceValues.allowance16_s = MpcCore.setPublic16(allowance);
        allAllowanceValues.allowance32_s = MpcCore.setPublic32(allowance);
        allAllowanceValues.allowance64_s = MpcCore.setPublic64(allowance);
        allAllowanceValues.allowance128_s = MpcCore.setPublic128(allowance);
        allAllowanceValues.allowance256_s = MpcCore.setPublic256(allowance);

        
        // Calculate the expected result 
        (gtUint8 newA_s, gtUint8 newB_s, gtBool res_s, gtUint8 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b8_s, allAmountValues.amount8_s, allAllowanceValues.allowance8_s);
        newA = MpcCore.decrypt(newA_s);
        newB = MpcCore.decrypt(newB_s);
        result = MpcCore.decrypt(res_s);
        newAllowance = MpcCore.decrypt(newAllowance_s);

        // Calculate the result with casting to 128
        computeAndCheckTransfer128(allGTCastingValues, allAmountValues, allAllowanceValues, newA, newB, result, newAllowance);

        // Calculate the result with casting to 256
        computeAndCheckTransfer256(allGTCastingValues, allAmountValues, allAllowanceValues, newA, newB, result, newAllowance);
        
        return (newA, newB, result, newAllowance); 
    }

}