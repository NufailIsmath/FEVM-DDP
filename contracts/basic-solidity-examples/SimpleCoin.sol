// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

error SimpleCoin__NotEnoughBalance();

contract SimpleCoin {
    mapping(address => uint256) balances;
    uint256 private i_tokensToBeMinted;

    event SentCoin(address receiver, uint256 amount);

    constructor(uint256 tokensToBeMinted) {
        balances[tx.origin] = tokensToBeMinted;
        i_tokensToBeMinted = tokensToBeMinted;
    }

    function sendCoin(address receiver, uint256 amount) public returns (bool sufficient) {
        if (balances[msg.sender] < amount) {
            // return false;
            revert SimpleCoin__NotEnoughBalance();
        }

        balances[msg.sender] -= amount;
        balances[receiver] += amount;
        //return true;

        emit SentCoin(receiver, amount);
    }

    function getBalanceInEth(address addr) public view returns (uint256) {
        return getBalance(addr) * 2;
    }

    function getBalance(address addr) public view returns (uint256) {
        return balances[addr];
    }

    function getMintedTokenBalance() public view returns (uint256) {
        return i_tokensToBeMinted;
    }
}
