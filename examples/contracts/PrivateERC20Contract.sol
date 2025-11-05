// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "MpcCore.sol";

// The provided Solidity contract is an implementation of an ERC20 token standard with enhanced privacy features.
// It aims to ensure the confidentiality of token transactions through encryption techniques while maintaining compatibility with the ERC20 standard.
//
// Key Features:
// Privacy Enhancement:
// The contract utilizes encryption techniques to encrypt sensitive data such as token balances and allowances. Encryption is performed using both user-specific and system-wide encryption keys to safeguard transaction details.
// Encrypted Balances and Allowances:
// Token balances and allowances are stored in encrypted form within the contract's state variables. This ensures that sensitive information remains confidential and inaccessible to unauthorized parties.
// Integration with MPC Core:
// The contract leverages functionalities provided by an external component called MpcCore. This component likely implements cryptographic operations such as encryption, decryption, and signature verification using techniques like Multi-Party Computation (MPC).
// Token Transfer Methods:
// The contract provides multiple transfer methods, allowing token transfers in both encrypted and clear (unencrypted) forms. Transfers can occur between addresses with encrypted token values or clear token values.
// Approval Mechanism:
// An approval mechanism is implemented to allow token holders to grant spending permissions (allowances) to other addresses. Approvals are also encrypted to maintain transaction privacy.
contract PrivateERC20Contract {

    // Events are emitted for token transfers (Transfer) and approvals (Approval). These events provide transparency and allow external observers to track token movements within the contract.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Transfer(address indexed _from, address indexed _to);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender);
    event Balance(address indexed _owner, ctUint256 _balance);
    event Allowance(address indexed _owner, ctUint256 _allowance);


    string private _name;
    string private _symbol;
    uint8 private _decimals = 5;    // Sets the number of decimal places for token amounts. Here, _decimals is 5,
                                    // allowing for transactions with precision up to 0.00001 tokens.
    uint256 private _totalSupply;

    // Mapping of balances of the token holders
    // The balances are stored encrypted by the system aes key
    mapping(address => ctUint256) private balances;
    // Mapping of allowances of the token holders
    mapping(address => mapping(address => ctUint256)) private allowances;

    // Create the contract with the name and symbol. Assign the initial supply of tokens to the contract creator.
    // params: name: the name of the token
    //         symbol: the symbol of the token
    //         initialSupply: the initial supply of the token assigned to the contract creator
    constructor(string memory name_, string memory symbol_, uint256 initialSupply) {
        _name = name_;
        _symbol = symbol_;
        _totalSupply = initialSupply;
        balances[msg.sender] = MpcCore.offBoard(MpcCore.setPublic256(initialSupply));
    }

    function name() public view returns (string memory){
        return _name;
    }

    function symbol() public view returns (string memory){
        return _symbol;
    }

    function decimals() public view returns (uint8){
        return _decimals;
    }

    function totalSupply() public view returns (uint256){
        return _totalSupply;
    }

    // The function returns the encrypted account balance utilizing the user's secret key.
    // Since the balance is initially encrypted internally using the system's AES key, the user cannot access it.
    // Thus, the balance undergoes re-encryption using the user's secret key.
    // As a result, the function is not designated as a "view" function.
    function balanceOf() public returns (ctUint256 memory){
        ctUint256 memory balance = balances[msg.sender];
        // The balance is saved encrypted using the system key. However, to allow the user to access it, the balance needs to be re-encrypted using the user key.
        // Therefore, we decrypt the balance (onBoard) and then encrypt it again using the user key (offBoardToUser).
        gtUint256 balanceGt = MpcCore.onBoard(balance);
        ctUint256 memory userBalance = MpcCore.offBoardToUser(balanceGt, msg.sender);
        emit Balance(msg.sender, userBalance);
        return userBalance;
    }

    // Transfers the amount of tokens given inside the IT (encrypted and signed value) to address _to
    // params: _to: the address to transfer to
    //         _itCT: the encrypted value of the amount to transfer
    //         _itSignature: the signature of the amount to transfer
    //         revealRes: indicates if we should reveal the result of the transfer
    // returns: In case revealRes is true, returns the result of the transfer. In case revealRes is false, always returns true
    function transfer(address _to, itUint256 calldata _it, bool revealRes) public returns (bool success){
        // Verify the IT and transfer the value
        gtBool result = contractTransfer(_to, MpcCore.validateCiphertext(_it));
        if (revealRes){
            return MpcCore.decrypt(result);
        } else {
            return true;
        }
    }

    // Transfers the amount of tokens to address _to
    // params: _to: the address to transfer to
    //         _value: the value of the amount to transfer
    //         revealRes: indicates if we should reveal the result of the transfer
    // returns: In case revealRes is true, returns the result of the transfer. In case revealRes is false, always returns true
    function transfer(address _to, uint256 _value, bool revealRes) public returns (bool success){
        gtBool result = contractTransferClear(_to, _value);

        if (revealRes){
            return MpcCore.decrypt(result);
        } else {
            return true;
        }
    }

    // Transfers the amount of tokens given inside the encrypted value to address _to
    // params: _to: the address to transfer to
    //         _value: the encrypted value of the amount to transfer
    // returns: The encrypted result of the transfer.
    function contractTransfer(address _to, gtUint256 _value) public returns (gtBool success){
        // Check for self-transfer
        if (msg.sender == _to) {
            emit Transfer(msg.sender, _to);
            return MpcCore.setPublic(true);
        }
        (gtUint256 fromBalance, gtUint256 toBalance) = getBalances(msg.sender, _to);
        (gtUint256 newFromBalance, gtUint256 newToBalance, gtBool result) = MpcCore.transfer(fromBalance, toBalance, _value);

        emit Transfer(msg.sender, _to);
        setNewBalances(msg.sender, _to, newFromBalance, newToBalance);

        return result;
    }

    // Transfers the amount of tokens to address _to
    // params: _to: the address to transfer to
    //         _value: the value of the amount to transfer
    // returns: The encrypted result of the transfer.
    function contractTransferClear(address _to, uint256 _value) public returns (gtBool success){
        // Check for self-transfer
        if (msg.sender == _to) {
            emit Transfer(msg.sender, _to, _value);
            return MpcCore.setPublic(true);
        }
        (gtUint256 fromBalance, gtUint256 toBalance) = getBalances(msg.sender, _to);
        (gtUint256 newFromBalance, gtUint256 newToBalance, gtBool result) = MpcCore.transfer(fromBalance, toBalance, _value);

        emit Transfer(msg.sender, _to, _value);
        setNewBalances(msg.sender, _to, newFromBalance, newToBalance);

        return result;
    }

    // Transfers the amount of tokens given inside the IT (encrypted and signed value) from address _from to address _to
    // params: _from: the address to transfer from
    //         __to: the address to transfer to
    //         _itCT: the encrypted value of the amount to transfer
    //         _itSignature: the signature of the amount to transfer
    //         revealRes: indicates if we should reveal the result of the transfer
    // returns: In case revealRes is true, returns the result of the transfer. In case revealRes is false, always returns true
    function transferFrom(address _from, address _to, itUint256 calldata _it, bool revealRes) public returns (bool success){
        // Verify the IT and transfer the value
        gtBool result = contractTransferFrom(_from, _to, MpcCore.validateCiphertext(_it));
        if (revealRes){
            return MpcCore.decrypt(result);
        } else {
            return true;
        }
    }

    // Transfers the amount of tokens from address _from to address _to
    // params: _from: the address to transfer from
    //         __to: the address to transfer to
    //         _value: the value of the amount to transfer
    //         revealRes: indicates if we should reveal the result of the transfer
    // returns: In case revealRes is true, returns the result of the transfer. In case revealRes is false, always returns true
    function transferFrom(address _from, address _to, uint256 _value, bool revealRes) public returns (bool success){
        gtBool result = contractTransferFromClear(_from, _to, _value);
        if (revealRes){
            return MpcCore.decrypt(result);
        } else {
            return true;
        }
    }

    // Transfers the amount of tokens given inside the encrypted value from address _from to address _to
    // params: _from: the address to transfer from
    //         _to: the address to transfer to
    //         _value: the encrypted value of the amount to transfer
    // returns: The encrypted result of the transfer.
    function contractTransferFrom(address _from, address _to, gtUint256 _value) public returns (gtBool success){

        (gtUint256 fromBalance, gtUint256 toBalance) = getBalances(_from, _to);
        gtUint256 allowance = MpcCore.onBoard(getGTAllowance(_from, msg.sender));

        // Check for self-transfer
        if (_from == _to) {
            emit Transfer(_from, _to);
            gtBool hasSufficientAllowance = MpcCore.ge(allowance, _value);
            return hasSufficientAllowance;
        }

        (gtUint256 newFromBalance, gtUint256 newToBalance, gtBool result, gtUint256 newAllowance) = MpcCore.transferWithAllowance(fromBalance, toBalance, _value, allowance);

        setApproveValue(_from, msg.sender, MpcCore.offBoard(newAllowance));
        emit Transfer(_from, _to);
        setNewBalances(_from, _to, newFromBalance, newToBalance);

        return result;
    }

    // Transfers the amount of tokens from address _from to address _to
    // params: _from: the address to transfer from
    //         _to: the address to transfer to
    //         _value: the value of the amount to transfer
    // returns: The encrypted result of the transfer.
    function contractTransferFromClear(address _from, address _to, uint256 _value) public returns (gtBool success){
        (gtUint256 fromBalance, gtUint256 toBalance) = getBalances(_from, _to);
        gtUint256 allowance = MpcCore.onBoard(getGTAllowance(_from, msg.sender));
        // Check for self-transfer
        if (_from == _to) {
            emit Transfer(_from, _to, _value);
            gtUint256 valueGt = MpcCore.setPublic256(_value);
            gtBool hasSufficientAllowance = MpcCore.ge(allowance, valueGt);
            return hasSufficientAllowance;
        }
        (gtUint256 newFromBalance, gtUint256 newToBalance, gtBool result, gtUint256 newAllowance) = MpcCore.transferWithAllowance(fromBalance, toBalance, _value, allowance);

        setApproveValue(_from, msg.sender, MpcCore.offBoard(newAllowance));
        emit Transfer(_from, _to, _value);
        setNewBalances(_from, _to, newFromBalance, newToBalance);

        return result;
    }

    // Returns the encrypted balances of the two addresses
    function getBalances(address _from, address _to) private returns (gtUint256, gtUint256){
        ctUint256 memory fromBalance = balances[_from];
        ctUint256 memory toBalance = balances[_to];

        gtUint256 gtFromBalance;
        gtUint256 gtToBalance;
        if (ctUint128.unwrap(fromBalance.ciphertextHigh) == 0 && ctUint128.unwrap(fromBalance.ciphertextLow) == 0){// 0 means that no allowance has been set
            gtFromBalance = MpcCore.setPublic256(0);
        } else {
            gtFromBalance = MpcCore.onBoard(fromBalance);
        }

        if (ctUint128.unwrap(toBalance.ciphertextHigh) == 0 && ctUint128.unwrap(toBalance.ciphertextLow) == 0){// 0 means that no allowance has been set
            gtToBalance = MpcCore.setPublic256(0);
        } else {
            gtToBalance = MpcCore.onBoard(toBalance);
        }

        return (gtFromBalance, gtToBalance);
    }

    // Sets the new encrypted balances of the two addresses
    function setNewBalances(address _from, address _to, gtUint256 newFromBalance, gtUint256 newToBalance) private {
        // Convert the gtUInt256 to ctUint256 and store it in the balances mapping
        balances[_from] = MpcCore.offBoard(newFromBalance);
        balances[_to] = MpcCore.offBoard(newToBalance);
    }

    // Sets the new allowance given inside the IT (encrypted and signed value) of the spender
    function approve(address _spender, itUint256 calldata _it) public returns (bool success){
        return approve(_spender, MpcCore.validateCiphertext(_it));
    }

    // Sets the new encrypted allowance of the spender
    function approve(address _spender, gtUint256 _value) public returns (bool success){
        address owner = msg.sender;
        setApproveValue(owner, _spender, MpcCore.offBoard(_value));
        emit Approval(owner, _spender);
        return true;
    }

    // Sets the new allowance of the spender
    function approveClear(address _spender, uint256 _value) public returns (bool success){
        address owner = msg.sender;
        gtUint256 gt = MpcCore.setPublic256(_value);
        setApproveValue(owner, _spender, MpcCore.offBoard(gt));
        emit Approval(owner, _spender, _value);
        return true;
    }

    // Returns the encrypted allowance of the spender. The encryption is done using the msg.sender aes key
    function allowance(address _owner, address _spender) public returns (ctUint256 memory remaining){
        require(_owner == msg.sender || _spender == msg.sender);
            
        ctUint256 memory remainingCt = getGTAllowance(_owner, _spender);
        gtUint256 remainingGt = MpcCore.onBoard(remainingCt);
        ctUint256 memory allowance = MpcCore.offBoardToUser(remainingGt, msg.sender);
        emit Allowance(msg.sender, allowance);

        return allowance;
    }

    // Returns the encrypted allowance of the spender. The encryption is done using the system aes key
    function getGTAllowance(address _owner, address _spender) private returns (ctUint256 memory remaining){
        ctUint256 memory allowance = allowances[_owner][_spender];
        if (ctUint128.unwrap(allowance.ciphertextHigh) == 0 && ctUint128.unwrap(allowance.ciphertextLow) == 0) {// 0 means that no allowance has been set
            gtUint256 zero = MpcCore.setPublic256(0);
            return MpcCore.offBoard(zero);
        } else {
            return allowance;
        }
    }

    // Sets the new encrypted allowance of the spender
    function setApproveValue(address _owner, address _spender, ctUint256 memory _value) private {
        allowances[_owner][_spender] = _value;
    }

}