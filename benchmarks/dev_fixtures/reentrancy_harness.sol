// SPDX-License-Identifier: MIT
// ponytail: minimal CEI violation for stock Slither reentrancy detectors (harness only).
pragma solidity ^0.8.20;

contract ReentrancyHarnessFixture {
    mapping(address => uint256) private balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
