contract Attacker {
    address constant pool = 0xabc...;
    address manipulated_contract;
    address exploited_contract;
	function StartAttack() public {
        // 1. callee is a constant assigned when deployed
        pool.flashloan(address(this), tokens, amounts, userData);
    }
    
    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata fees,
        bytes calldata userData
    ) external {
        // 2. callee is stored in the storage
        manipulated_contract.changeState(source_1);
        // some calls...
        exploited_contract.takeProfit(source_2);
        // pay back ...
    }
}


contract Pool {
    function flashLoan(
        IFlashLoanRecipient recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external override nonReentrant whenNotPaused {
        for (uint256 i = 0; i < tokens.length; ++i) {
            // transfer assets to the recipient
            token.safeTransfer(address(recipient), amount);
        }
        // invoke the recipient's callback
        // 3. callee is a function argument
        recipient.receiveFlashLoan(tokens, amounts, feeAmounts, userData);
    }
}

contract ManipulatedContract {
    mapping(address => uint256) public balances;
    function changeState(address to, uint amount) public {
        balances[to] += amount;
    }
}

contract ExplitedContract {
    address manipulated_contract;
    function takeProfit(address to) public {
        to.transfer(manipulated_contract.balanceOf(address(this)));
    }
}