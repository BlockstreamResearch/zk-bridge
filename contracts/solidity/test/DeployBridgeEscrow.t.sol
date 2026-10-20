// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {BridgeEscrow} from "../contracts/BridgeEscrow.sol";
import {DeployBridgeEscrow} from "../script/DeployBridgeEscrow.s.sol";

interface Vm {
    function chainId(uint256 newChainId) external;
    function warp(uint256 timestamp) external;
    function readFile(string calldata path) external view returns (string memory);
    function expectRevert(bytes calldata revertData) external;
}

/// The deployment script's parameter reading and read-back, exposed.
contract DeployHarness is DeployBridgeEscrow {
    function parse(string memory json) external pure returns (Params memory) {
        return read(json);
    }

    function check(BridgeEscrow e, Params memory p) external view {
        readBack(e, p);
    }
}

/// The read-back of DeployBridgeEscrow.s.sol over the current deployment's parameter fixture: it accepts an
/// escrow built from that file and refuses one whose light client starts elsewhere.
contract DeployBridgeEscrowTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string constant PARAMS = "test/fixtures/deploy-escrow-params.json";
    /// Liquid testnet block 2668999 as explorers display it: the checkpoint hash with its bytes reversed.
    bytes32 constant BLOCK_ID = 0x4f5cda72b48376dd143e1dc5780168df233b99e2fb434c4544d8e7f3dc714ef9;
    /// When the parameters were written; their deposit window runs from here.
    uint256 constant WRITTEN = 1_792_500_000;

    DeployHarness immutable h = new DeployHarness();

    function params() internal view returns (DeployBridgeEscrow.Params memory) {
        return h.parse(vm.readFile(PARAMS));
    }

    function deploy(DeployBridgeEscrow.Params memory p) internal returns (BridgeEscrow) {
        vm.chainId(11_155_111);
        vm.warp(WRITTEN);
        return new BridgeEscrow(p.asset, p.minConfirmations, p.maxRelayLag, p.admission, p.checkpoint);
    }

    function refused(string memory reason) internal {
        vm.expectRevert(abi.encodeWithSignature("Error(string)", reason));
    }

    function reversed(bytes32 x) internal pure returns (bytes32 y) {
        for (uint256 i; i < 32; i++) {
            y |= bytes32(uint256(uint8(x[i])) << (8 * i));
        }
    }

    function testReadBackAcceptsTheParameterFile() public {
        DeployBridgeEscrow.Params memory p = params();
        BridgeEscrow e = deploy(p);
        h.check(e, p);
        require(reversed(e.lcTipHash()) == BLOCK_ID, "the tip is the checkpoint block in internal byte order");
    }

    function testReadBackRefusesTheDisplayedByteOrder() public {
        DeployBridgeEscrow.Params memory p = params();
        DeployBridgeEscrow.Params memory wrong = params();
        wrong.checkpoint.hash = BLOCK_ID;
        BridgeEscrow e = deploy(wrong);
        refused("lcTipHash");
        h.check(e, p);
    }

    function testReadBackRefusesAnotherCheckpointHeight() public {
        DeployBridgeEscrow.Params memory p = params();
        DeployBridgeEscrow.Params memory wrong = params();
        wrong.checkpoint.height -= 1000; // the last block of the previous epoch
        BridgeEscrow e = deploy(wrong);
        refused("lcTipHeight");
        h.check(e, p);
    }

    function testReadBackRefusesAnotherEpochLength() public {
        DeployBridgeEscrow.Params memory p = params();
        DeployBridgeEscrow.Params memory wrong = params();
        wrong.checkpoint.epochLength = 500; // 2668999 also ends an epoch of 500 blocks
        BridgeEscrow e = deploy(wrong);
        refused("EPOCH_LENGTH");
        h.check(e, p);
    }
}
