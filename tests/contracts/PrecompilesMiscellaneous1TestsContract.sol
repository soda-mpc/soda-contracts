// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesMiscellaneous1TestsContract {

    uint256 random = 0;
    uint256 randomBounded = 0;
    bool andRes;
    bool orRes;
    bool xorRes;
    bool notRes;
    bool eqRes;
    bool neqRes;
    bool muxRes;
    bool onboardRes;

    uint8 validateCiphertextRes;
    uint256 validateCiphertext256Res;

    uint8 validateCiphertextEip191Res;
    uint256 validateCiphertext256Eip191Res;

    function getRandom() public view returns (uint256) {
        return random;
    }

    function getRandomBounded() public view returns (uint256) {
        return randomBounded;
    }

    function getBooleanResults() public view returns (bool, bool, bool, bool, bool, bool, bool, bool) {
        return (andRes, orRes, xorRes, notRes, eqRes, neqRes, muxRes, onboardRes);
    }
    
    function getValidateCiphertextResult() public view returns (uint8) {
        return validateCiphertextRes;
    }

    function getValidateCiphertextEip191Result() public view returns (uint8) {
        return validateCiphertextEip191Res;
    }

    function getValidateCiphertext256Result() public view returns (uint256) {
        return validateCiphertext256Res;
    }

    function getValidateCiphertext256Eip191Result() public view returns (uint256) {
        return validateCiphertext256Eip191Res;
    }

    uint constant MAX_SIZE_8_BITS = 10; 
    uint constant MAX_SIZE_16_BITS = 3; 
    uint constant MAX_SIZE_32_BITS = 3; 
    uint constant MAX_SIZE_64_BITS = 2;
    uint constant MAX_BOOL_SIZE = 40; 

    function checkNotAllEqual(uint256[MAX_SIZE_8_BITS] memory randoms, uint size) private {
        // Count how many randoms are equal
        uint numEqual = 1;
        for (uint i = 1; i < size; i++) {
            if (randoms[0] == randoms[i]){
                numEqual++;
            }
        }
        require(numEqual != size, "randomTest: random failed, all values are the same");
    }

    function randomTest() public returns (uint256) {
        return randTest_(false, 0);
    }

    function checkBound(uint256[MAX_SIZE_8_BITS] memory randoms, uint size, uint8 numBits) public {
        for (uint i = 0; i < size; i++) {
            require(randoms[i] < (1 << numBits), "randomTest: random failed, out of bounds");
        }
    }

    function randomBoundedTest(uint8 numBits) public returns (uint256) {
        return randTest_(true, numBits); 
    }

    function randTest_(bool isBounded, uint8 numBits) public returns (uint256) {
        uint size = MAX_SIZE_8_BITS;
        uint256[MAX_SIZE_8_BITS] memory randoms;
        // Generate gtUint8 randoms
        for (uint i = 0; i < size; i++) {
            if(!isBounded){
                randoms[i] = MpcCore.decrypt(MpcCore.rand8());
            } else {
                randoms[i] = MpcCore.decrypt(MpcCore.randBoundedBits8(numBits));
            }
        }
        
        if (isBounded) {
            // Check that all randoms are in bounds
            checkBound(randoms, size, numBits);
        }
        // Check that not all the generated random values are the same
        checkNotAllEqual(randoms, size);

        // In case of bounded random, the bit size does not matter because the bounded bits can be small. 
        // So the max size remain as in 8 bits.
        // In case of unbounded random, max size can be reduced.
        if (!isBounded){ 
            size = MAX_SIZE_16_BITS;
        }
        // Generate gtUint16 randoms
        for (uint i = 0; i < size; i++) {
            if(!isBounded){
                randoms[i] = MpcCore.decrypt(MpcCore.rand16());
            } else {
                randoms[i] = MpcCore.decrypt(MpcCore.randBoundedBits16(numBits));
            }
        }
        if (isBounded) {
            // Check that all randoms are in bounds
            checkBound(randoms, size, numBits);
        }
        // Check that not all the generated random values are the same
        checkNotAllEqual(randoms, size);

        // Generate gtUint32 randoms
        if (!isBounded){ 
            size = MAX_SIZE_32_BITS;
        }
        for (uint i = 0; i < size; i++) {
            if(!isBounded){
                randoms[i] = MpcCore.decrypt(MpcCore.rand32());
            } else {
                randoms[i] = MpcCore.decrypt(MpcCore.randBoundedBits32(numBits));
            }
        }
        if (isBounded) {
            // Check that all randoms are in bounds
            checkBound(randoms, size, numBits);
        }
        // Check that not all the generated random values are the same
        checkNotAllEqual(randoms, size);

        // Generate gtUint64 randoms
        if (!isBounded){ 
            size = MAX_SIZE_64_BITS;
        }
        for (uint i = 0; i < size; i++) {
            if(!isBounded){
                randoms[i] = MpcCore.decrypt(MpcCore.rand64());
            } else {
                randoms[i] = MpcCore.decrypt(MpcCore.randBoundedBits64(numBits));
            }
        }

        if (isBounded) {
            // Check that all randoms are in bounds
            checkBound(randoms, size, numBits);
            randomBounded = randoms[0];
        } else {
            random = randoms[0];
        }
        // Check that not all the generated random values are the same
        checkNotAllEqual(randoms, size);

        // Generate gtUint128 randoms
        for (uint i = 0; i < size; i++) {
            if(!isBounded){
                randoms[i] = MpcCore.decrypt(MpcCore.rand128());
            } else {
                randoms[i] = MpcCore.decrypt(MpcCore.randBoundedBits128(numBits));
            }
        }

        if (isBounded) {
            // Check that all randoms are in bounds
            checkBound(randoms, size, numBits);
            randomBounded = randoms[0];
        } else {
            random = randoms[0];
        }
        // Check that not all the generated random values are the same
        checkNotAllEqual(randoms, size);

        // Generate gtUint256 randoms
        for (uint i = 0; i < size; i++) {
            if(!isBounded){
                randoms[i] = MpcCore.decrypt(MpcCore.rand256());
            } else {
                randoms[i] = MpcCore.decrypt(MpcCore.randBoundedBits256(numBits));
            }
        }

        if (isBounded) {
            // Check that all randoms are in bounds
            checkBound(randoms, size, numBits);
            randomBounded = randoms[0];
        } else {
            random = randoms[0];
        }
        // Check that not all the generated random values are the same
        checkNotAllEqual(randoms, size);

        // Generate gtBool randoms
        bool randRes = MpcCore.decrypt(MpcCore.rand());
        uint numEqual = 0;
        for (uint i = 0; i < MAX_BOOL_SIZE; i++) {
            if (randRes == MpcCore.decrypt(MpcCore.rand())) {
                numEqual++;
            }
        }
        require(numEqual < MAX_BOOL_SIZE, "boolean random failed, all values are the same");
        
        return random; 
    }

    function booleanTest(bool a, bool b, bool bit) public {
        gtBool aGT = MpcCore.setPublic(a);
        gtBool bGT = MpcCore.setPublic(b);
        gtBool bitGT = MpcCore.setPublic(bit);

        andRes = MpcCore.decrypt(MpcCore.and(aGT, bGT));
        orRes = MpcCore.decrypt(MpcCore.or(aGT, bGT));
        xorRes = MpcCore.decrypt(MpcCore.xor(aGT, bGT));
        notRes = MpcCore.decrypt(MpcCore.not(aGT));
        eqRes = MpcCore.decrypt(MpcCore.eq(aGT, bGT));
        neqRes = MpcCore.decrypt(MpcCore.ne(aGT, bGT));
        muxRes = MpcCore.decrypt(MpcCore.mux(bitGT, aGT, bGT));

        ctBool cipher = MpcCore.offBoard(aGT);
        onboardRes = MpcCore.decrypt(MpcCore.onBoard(cipher)); 
    }

    // When invoking this test function, all ciphertexts share the same value but are 
    // cast to four different types: ctUint8, ctUint16, ctUint32, and ctUint64. 
    // Consequently, there is a single signature covering all these ciphertexts.
    function validateCiphertextTest(ctUint8 ct8, ctUint16 ct16, ctUint32 ct32, ctUint64 ct64, ctUint128 ct128, bytes calldata signature) public returns (uint8){
        // Create ITs from ciphertext and signature
        itUint8 memory it8;
        it8.ciphertext = ct8;
        it8.signature = signature;

        itUint16 memory it16;
        it16.ciphertext = ct16;
        it16.signature = signature;

        itUint32 memory it32;
        it32.ciphertext = ct32;
        it32.signature = signature;

        itUint64 memory it64;
        it64.ciphertext = ct64;
        it64.signature = signature;

        itUint128 memory it128;
        it128.ciphertext = ct128;
        it128.signature = signature;

        validateCiphertextRes = MpcCore.decrypt(MpcCore.validateCiphertext(it8));

        uint16 result16 = MpcCore.decrypt(MpcCore.validateCiphertext(it16));
        require(result16 == validateCiphertextRes, "validateCiphertextTest: validateCiphertext with 16 bits failed");

        uint32 result32 = MpcCore.decrypt(MpcCore.validateCiphertext(it32));
        require(result32 == validateCiphertextRes, "validateCiphertextTest: validateCiphertext with 32 bits failed");

        uint64 result64 = MpcCore.decrypt(MpcCore.validateCiphertext(it64));
        require(result64 == validateCiphertextRes, "validateCiphertextTest: validateCiphertext with 64 bits failed");

        uint128 result128 = MpcCore.decrypt(MpcCore.validateCiphertext(it128));
        require(result128 == validateCiphertextRes, "validateCiphertextTest: validateCiphertext with 128 bits failed");
        
        return validateCiphertextRes;
    }

     // When invoking this test function, all ciphertexts share the same value but are 
    // cast to four different types: ctUint8, ctUint16, ctUint32, and ctUint64. 
    // Consequently, there is a single signature covering all these ciphertexts.
    function validateCiphertextTest191(ctUint8 ct8, ctUint16 ct16, ctUint32 ct32, ctUint64 ct64, ctUint128 ct128, bytes calldata signature) public returns (uint8){
        // Create ITs from ciphertext and signature
        itUint8 memory it8;
        it8.ciphertext = ct8;
        it8.signature = signature;

        itUint16 memory it16;
        it16.ciphertext = ct16;
        it16.signature = signature;

        itUint32 memory it32;
        it32.ciphertext = ct32;
        it32.signature = signature;

        itUint64 memory it64;
        it64.ciphertext = ct64;
        it64.signature = signature;

        itUint128 memory it128;
        it128.ciphertext = ct128;
        it128.signature = signature;

        validateCiphertextEip191Res = MpcCore.decrypt(MpcCore.validateCiphertext(it8));

        uint16 result16 = MpcCore.decrypt(MpcCore.validateCiphertext(it16));
        require(result16 == validateCiphertextEip191Res, "validateCiphertextTest: validateCiphertext with 16 bits failed");

        uint32 result32 = MpcCore.decrypt(MpcCore.validateCiphertext(it32));
        require(result32 == validateCiphertextEip191Res, "validateCiphertextTest: validateCiphertext with 32 bits failed");

        uint64 result64 = MpcCore.decrypt(MpcCore.validateCiphertext(it64));
        require(result64 == validateCiphertextEip191Res, "validateCiphertextTest: validateCiphertext with 64 bits failed");

        uint128 result128 = MpcCore.decrypt(MpcCore.validateCiphertext(it128));
        require(result128 == validateCiphertextEip191Res, "validateCiphertextTest: validateCiphertext with 128 bits failed");
        
        return validateCiphertextEip191Res;
    }

    function validateCiphertext256Test(itUint256 calldata it256) public returns (uint256){
        validateCiphertext256Res = MpcCore.decrypt(MpcCore.validateCiphertext(it256));
        return validateCiphertext256Res;
    }

    function validateCiphertext256Test191(itUint256 calldata it256) public returns (uint256){
        validateCiphertext256Eip191Res = MpcCore.decrypt(MpcCore.validateCiphertext(it256));
        return validateCiphertext256Eip191Res;
    }

}