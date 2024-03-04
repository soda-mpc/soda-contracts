// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

contract PrecompilesMiscellaneous1TestsContract {

    uint64 random = 0;

    function getRandom() public view returns (uint64) {
        return random;
    }

    uint constant MAX_SIZE_8_BITS = 10; 
    uint constant MAX_SIZE_16_BITS = 3; 
    uint constant MAX_SIZE_32_BITS = 3; 
    uint constant MAX_SIZE_64_BITS = 2; 
    uint constant MAX_BOOL_SIZE = 40; 

    function checkNotAllEqual(uint64[MAX_SIZE_8_BITS] memory randoms, uint size) private {
        // Count how many randoms are equal
        uint numEqual = 1;
        for (uint i = 1; i < size; i++) {
            if (randoms[0] == randoms[i]){
                numEqual++;
            }
        }
        require(numEqual != size, "randomTest: random failed, all values are the same");
    }

    function randomTest() public returns (uint64) {
        return randTest_(false, 0);
    }

    function checkBound(uint64[MAX_SIZE_8_BITS] memory randoms, uint size, uint8 numBits) public {
        for (uint i = 0; i < size; i++) {
            require(randoms[i] < (1 << numBits), "randomTest: random failed, out of bounds");
        }
    }

    function randomBoundedTest(uint8 numBits) public returns (uint64) {
        return randTest_(true, numBits); 
    }

    function randTest_(bool isBounded, uint8 numBits) public returns (uint64) {
        uint size = MAX_SIZE_8_BITS;
        uint64[MAX_SIZE_8_BITS] memory randoms;
        // Generate gtUint8 randoms
        for (uint i = 0; i < size; i++) {
            if(!isBounded){
                randoms[i] = MpcCore.decrypt(MpcCore.rand8());
            } else {
                randoms[i] = MpcCore.decrypt(MpcCore.randBoundedBits8(numBits));
            }
        }
        random = randoms[0];
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
        }
        // Check that not all the generated random values are the same
        checkNotAllEqual(randoms, size);
        
        return random; 
    }

}