// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {BridgeEscrow} from "../contracts/BridgeEscrow.sol";
import {LiquidLightClient} from "../contracts/LiquidLightClient.sol";
import {BeaconRootsMock, SepoliaBeacon} from "./SepoliaBeacon.sol";

interface Vm {
    struct Wallet {
        address addr;
        uint256 publicKeyX;
        uint256 publicKeyY;
        uint256 privateKey;
    }

    function warp(uint256 timestamp) external;
    function etch(address target, bytes calldata code) external;
    function skip(bool skipTest) external;
    function expectRevert(bytes4 revertData) external;
    function createWallet(uint256 privateKey) external returns (Wallet memory);
    function exists(string calldata path) external view returns (bool);
    function readFile(string calldata path) external view returns (string memory);
    function envOr(string calldata name, string calldata defaultValue) external view returns (string memory);
    function createSelectFork(string calldata urlOrAlias, uint256 blockNumber) external returns (uint256);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonBytes32Array(string calldata json, string calldata key) external pure returns (bytes32[] memory);
}

/// checkFork against real Sepolia data: the check of the SSZ layout that the contract states and SepoliaBeacon
/// only models.
///
/// testRealSepoliaStateRoot needs no tool output. Its fixture is a public Sepolia (Gloas) light-client finality
/// update, as served, of attested slot 11381920. Its 9-node finality branch proves the finalized checkpoint's
/// root at generalized index 735 of the attested state, and the test walks it to the header's state_root. It then
/// builds a checkFork proof from that branch and the header alone, and checkFork must recompute the real block
/// root. Only the BeaconRootsMock stands in for the chain, since EIP-4788 keeps a root for about a day.
///
/// testRealSepoliaStateProof takes the output of
///   tools/liquid-relay/fork_proof.py build --out contracts/solidity/test/fixtures/sepolia-fork-proof.json
/// which the tool checked against the EIP-4788 contract's root for `timestamp`, recorded as blockRoot, and against
/// the header of the execution block with that timestamp, recorded as executionBlock; skipped while the fixture is
/// absent. With SEPOLIA_FORK_PROOF_RPC set to a Sepolia execution RPC, the same proof also runs on a fork of
/// Sepolia at executionBlock, against the real EIP-4788 contract. That block is fixed, so the run gives the same
/// answer at any time, given an RPC that serves the block's state: an archive node, or any node while the block is
/// recent. `fork_proof.py verify` checks the recorded root against block headers on any node, at any time.
contract BridgeEscrowForkProofTest is SepoliaBeacon {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string constant UPDATE = "test/fixtures/sepolia-finality-update-11381920.json";
    string constant FIXTURE = "test/fixtures/sepolia-fork-proof.json";
    uint64 constant SECONDS_PER_SLOT = 12;
    uint256 constant FINALIZED_ROOT_GINDEX = 735;

    struct Header {
        uint64 slot;
        uint64 proposerIndex;
        bytes32 parentRoot;
        bytes32 stateRoot;
        bytes32 bodyRoot;
    }

    function testRealSepoliaStateRoot() public {
        string memory json = vm.readFile(UPDATE);
        Header memory attested = headerOf(json, ".data.attested_header.beacon");
        (bytes32 node11, bytes32 activeFields) = finalityNodes(json, attested);
        BridgeEscrow.BeaconProof memory p = realProof(attested, node11, activeFields);

        vm.etch(BEACON_ROOTS, address(new BeaconRootsMock()).code);
        BeaconRootsMock(BEACON_ROOTS).set(p.timestamp, headerRoot(attested));
        vm.warp(p.timestamp);
        BridgeEscrow escrow = deploy();
        require(escrow.checkFork(p), "the real Gloas state, under the pin");
        require(escrow.forkCheckedAt() == GENESIS + attested.slot * SECONDS_PER_SLOT, "forkCheckedAt = slot time");
        // Node 10 commits fields 1 to 4, so the fork is bound too.
        p.previousVersion = GLOAS;
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        escrow.checkFork(p);
    }

    /// Walks the fixture's finality branch from field 20's root, finalized_checkpoint.root, at node 735 to the
    /// attested state root, and returns the nodes it fixes that checkFork takes: 11, passed on the way, and 3.
    function finalityNodes(string memory json, Header memory attested)
        internal
        pure
        returns (bytes32 node11, bytes32 activeFields)
    {
        Header memory finalized = headerOf(json, ".data.finalized_header.beacon");
        bytes32[] memory branch = vm.parseJsonBytes32Array(json, ".data.finality_branch");
        require(attested.slot == 11_381_920 && finalized.slot == 11_381_856 && branch.length == 9, "the fixture");
        bytes32 at = headerRoot(finalized);
        uint256 g = FINALIZED_ROOT_GINDEX;
        for (uint256 i = 0; i < 9; i++) {
            at = g & 1 == 1 ? sha256(abi.encodePacked(branch[i], at)) : sha256(abi.encodePacked(at, branch[i]));
            g >>= 1;
            if (g == 11) node11 = at;
        }
        require(g == 1 && at == attested.stateRoot, "the finality branch reaches the attested state root");
        require(branch[0] == le64(finalized.slot / 32), "node 734: the checkpoint's epoch");
        // Nodes 4 and 3: genesis_time as a bare chunk, and 46 active fields.
        require(branch[7] == le64(GENESIS) && branch[8] == activeBits(0, 45), "nodes 4 and 3");
        activeFields = branch[8];
    }

    /// checkFork's proof of the attested state under Gloas, from its header and the branch's nodes 11 and 3. The
    /// state after a block holds that block's header, with a zero state_root, as latest_block_header (node 43).
    function realProof(Header memory attested, bytes32 node11, bytes32 activeFields)
        internal
        pure
        returns (BridgeEscrow.BeaconProof memory p)
    {
        Header memory latest =
            Header(attested.slot, attested.proposerIndex, attested.parentRoot, bytes32(0), attested.bodyRoot);
        p.timestamp = GENESIS + (attested.slot + 1) * SECONDS_PER_SLOT;
        p.genesisTime = GENESIS;
        p.genesisValidatorsRoot = GVR;
        p.slot = attested.slot;
        p.previousVersion = FULU;
        p.currentVersion = GLOAS;
        p.epoch = GLOAS_EPOCH;
        p.stateBranch = [headerRoot(latest), node11];
        p.activeFields = activeFields;
        p.blockBranch = [
            attested.parentRoot,
            sha256(abi.encodePacked(le64(attested.slot), le64(attested.proposerIndex))),
            sha256(abi.encodePacked(sha256(abi.encodePacked(attested.bodyRoot, bytes32(0))), zeroNode(1)))
        ];
    }

    function testRealSepoliaStateProof() public {
        if (!vm.exists(FIXTURE)) {
            vm.skip(true);
            return;
        }
        string memory json = vm.readFile(FIXTURE);
        BridgeEscrow.BeaconProof memory p = proofOf(json);
        require(p.genesisTime == GENESIS && p.genesisValidatorsRoot == GVR, "Sepolia's genesis");
        string memory rpc = vm.envOr("SEPOLIA_FORK_PROOF_RPC", string(""));
        if (bytes(rpc).length != 0) {
            // The real EIP-4788 contract, in the state after the execution block whose header names blockRoot.
            vm.createSelectFork(rpc, executionBlock(json));
            require(block.timestamp == p.timestamp, "the fork is at the proof's execution block");
        } else {
            vm.etch(BEACON_ROOTS, address(new BeaconRootsMock()).code);
            BeaconRootsMock(BEACON_ROOTS).set(p.timestamp, vm.parseJsonBytes32(json, ".blockRoot"));
            vm.warp(p.timestamp);
        }
        BridgeEscrow escrow = deploy();

        bool pinned = escrow.checkFork(p);
        require(pinned == (p.currentVersion == GLOAS && p.epoch == GLOAS_EPOCH), "pinned iff Gloas");
        if (pinned) {
            require(escrow.forkCheckedAt() == p.genesisTime + p.slot * SECONDS_PER_SLOT, "forkCheckedAt = slot time");
        } else {
            require(escrow.depositsEnd() == block.timestamp, "any other fork ends deposits");
        }
        // Every proven field is bound: another slot is a different state.
        p.slot += 1;
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        escrow.checkFork(p);
    }

    /// tools/liquid-relay/fork_proof.py and ui/lib/bridge.js encode checkFork's calldata by this signature.
    function testCheckForkSignature() public pure {
        require(
            BridgeEscrow.checkFork.selector
                == bytes4(
                    keccak256(
                        "checkFork((uint64,uint64,bytes32,uint64,bytes4,bytes4,uint64,bytes32[2],bytes32,bytes32[3]))"
                    )
                ),
            "checkFork signature"
        );
    }

    /// The fixture's executionBlock. A fixture recorded before the tool wrote it gets it from
    /// `fork_proof.py verify --proof contracts/solidity/test/fixtures/sepolia-fork-proof.json --write`.
    function executionBlock(string memory json) internal pure returns (uint256) {
        try vm.parseJsonUint(json, ".executionBlock.number") returns (uint256 number) {
            return number;
        } catch {
            revert("the fixture records no executionBlock: run fork_proof.py verify --write on it");
        }
    }

    function headerOf(string memory json, string memory key) internal pure returns (Header memory h) {
        h.slot = uint64(vm.parseJsonUint(json, string.concat(key, ".slot")));
        h.proposerIndex = uint64(vm.parseJsonUint(json, string.concat(key, ".proposer_index")));
        h.parentRoot = vm.parseJsonBytes32(json, string.concat(key, ".parent_root"));
        h.stateRoot = vm.parseJsonBytes32(json, string.concat(key, ".state_root"));
        h.bodyRoot = vm.parseJsonBytes32(json, string.concat(key, ".body_root"));
    }

    /// BeaconBlockHeader's root: five fields in an 8-leaf tree.
    function headerRoot(Header memory h) internal pure returns (bytes32 root) {
        bytes32[] memory fields = new bytes32[](8);
        fields[0] = le64(h.slot);
        fields[1] = le64(h.proposerIndex);
        fields[2] = h.parentRoot;
        fields[3] = h.stateRoot;
        fields[4] = h.bodyRoot;
        (root,) = merkle(fields, 0);
    }

    function zeroNode(uint256 depth) internal pure returns (bytes32 z) {
        for (uint256 i = 0; i < depth; i++) {
            z = sha256(abi.encodePacked(z, z));
        }
    }

    function proofOf(string memory json) internal pure returns (BridgeEscrow.BeaconProof memory p) {
        p.timestamp = uint64(vm.parseJsonUint(json, ".proof.timestamp"));
        p.genesisTime = uint64(vm.parseJsonUint(json, ".proof.genesisTime"));
        p.genesisValidatorsRoot = vm.parseJsonBytes32(json, ".proof.genesisValidatorsRoot");
        p.slot = uint64(vm.parseJsonUint(json, ".proof.slot"));
        p.previousVersion = bytes4(vm.parseJsonBytes(json, ".proof.previousVersion"));
        p.currentVersion = bytes4(vm.parseJsonBytes(json, ".proof.currentVersion"));
        p.epoch = uint64(vm.parseJsonUint(json, ".proof.epoch"));
        bytes32[] memory state = vm.parseJsonBytes32Array(json, ".proof.stateBranch");
        bytes32[] memory blk = vm.parseJsonBytes32Array(json, ".proof.blockBranch");
        require(state.length == 2 && blk.length == 3, "branch lengths");
        p.stateBranch = [state[0], state[1]];
        p.activeFields = vm.parseJsonBytes32(json, ".proof.activeFields");
        p.blockBranch = [blk[0], blk[1], blk[2]];
    }

    /// An escrow pinned to Gloas, as a deployment of the current guest schedule is, over a synthetic Liquid checkpoint.
    function deploy() internal returns (BridgeEscrow) {
        Vm.Wallet memory w = vm.createWallet(0x5eed);
        bytes memory script = abi.encodePacked(
            hex"51" hex"21",
            (w.publicKeyY & 1) == 1 ? bytes1(0x03) : bytes1(0x02),
            bytes32(w.publicKeyX),
            hex"51" hex"ae"
        );
        uint256[] memory ys = new uint256[](1);
        ys[0] = w.publicKeyY;
        LiquidLightClient.Checkpoint memory cp =
            LiquidLightClient.Checkpoint(1000, 1999, keccak256("checkpoint block"), script, ys);
        BridgeEscrow.Admission memory admission = BridgeEscrow.Admission(
            uint64(block.timestamp + 30 days), type(uint64).max, address(0), 1 hours, GVR, GLOAS, GLOAS_EPOCH
        );
        return new BridgeEscrow(keccak256("bridge asset"), 2, 1 days, admission, cp);
    }
}
