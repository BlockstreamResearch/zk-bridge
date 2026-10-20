// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {BridgeEscrow} from "../contracts/BridgeEscrow.sol";

/// Stands in for the EIP-4788 contract: the beacon block root stored for a timestamp, or a revert.
contract BeaconRootsMock {
    mapping(uint256 => bytes32) private roots;

    function set(uint256 timestamp, bytes32 root) external {
        roots[timestamp] = root;
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        require(input.length == 32, "input");
        bytes32 root = roots[abi.decode(input, (uint256))];
        require(root != bytes32(0), "no root");
        return abi.encode(root);
    }
}

/// A synthetic Sepolia beacon chain for BridgeEscrow.checkFork: beacon states built field by field and hashed by
/// the EIP-7916 recursion, not by checkFork's fixed path, whose block roots the tests store in a BeaconRootsMock
/// etched at BEACON_ROOTS. The layout is checked against real Sepolia data in BridgeEscrowForkProof.t.sol.
abstract contract SepoliaBeacon {
    address constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    // Sepolia's beacon chain: genesis time and validators root, and the guest's last fork, Gloas.
    uint64 constant GENESIS = 1_655_733_600;
    bytes32 constant GVR = 0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078;
    bytes4 constant FULU = 0x90000075;
    bytes4 constant GLOAS = 0x90000076;
    uint64 constant GLOAS_EPOCH = 353_024;

    /// The SSZ chunk of a uint64, byte by byte.
    function le64(uint64 x) internal pure returns (bytes32) {
        bytes memory b = new bytes(32);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(x >> (8 * i)));
        }
        return bytes32(b);
    }

    /// The SSZ root of a power-of-two list of chunks, and the branch of chunk `index`, leaf level first.
    function merkle(bytes32[] memory level, uint256 index)
        internal
        pure
        returns (bytes32 root, bytes32[] memory branch)
    {
        uint256 depth = 0;
        while ((uint256(1) << depth) < level.length) depth++;
        branch = new bytes32[](depth);
        for (uint256 d = 0; d < depth; d++) {
            branch[d] = level[index ^ 1];
            bytes32[] memory up = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < up.length; i++) {
                up[i] = sha256(abi.encodePacked(level[2 * i], level[2 * i + 1]));
            }
            level = up;
            index >>= 1;
        }
        root = level[0];
    }

    /// EIP-7916's progressive tree of chunks[from:], in levels of width, 4 * width, ... chunks: each node has
    /// its level's binary subtree on the left and the rest on the right, and a zero chunk ends it.
    function progressive(bytes32[] memory chunks, uint256 from, uint256 width) internal pure returns (bytes32) {
        if (from >= chunks.length) return bytes32(0);
        bytes32[] memory level = new bytes32[](width);
        for (uint256 i = 0; i < width && from + i < chunks.length; i++) {
            level[i] = chunks[from + i];
        }
        (bytes32 left,) = merkle(level, 0);
        return sha256(abi.encodePacked(left, progressive(chunks, from + width, 4 * width)));
    }

    /// The active-fields bits of a ProgressiveContainer (EIP-7495) whose fields `first` to `last` are active, as
    /// its root mixes them in: field i at bit i % 8 of byte i / 8.
    function activeBits(uint256 first, uint256 last) internal pure returns (bytes32) {
        bytes memory b = new bytes(32);
        for (uint256 i = first; i <= last; i++) {
            b[i / 8] |= bytes1(uint8(1) << uint8(i % 8));
        }
        return bytes32(b);
    }

    /// A ProgressiveContainer beacon state with active-fields bits `bits` (Gloas's on Sepolia are 46 ones), as many
    /// fields as its last active one, p's fields 0 to 3 and filler for the rest. An inactive field's root is zero.
    /// Returns its root, and the nodes checkFork takes: 43, 11 and 3.
    function stateTree(BridgeEscrow.BeaconProof memory p, bytes32 bits)
        internal
        pure
        returns (bytes32 root, bytes32[2] memory branch, bytes32 activeFields)
    {
        bytes32[] memory fork = new bytes32[](4);
        fork[0] = bytes32(p.previousVersion);
        fork[1] = bytes32(p.currentVersion);
        fork[2] = le64(p.epoch);
        uint256 n = 256;
        while (n > 5 && uint8(bits[(n - 1) / 8]) & (uint8(1) << uint8((n - 1) % 8)) == 0) n--;
        bytes32[] memory fields = new bytes32[](n);
        fields[0] = le64(p.genesisTime);
        fields[1] = p.genesisValidatorsRoot;
        fields[2] = le64(p.slot);
        (fields[3],) = merkle(fork, 0);
        for (uint256 i = 4; i < n; i++) {
            fields[i] = keccak256(abi.encode("state field", i, p.slot));
        }
        for (uint256 i = 0; i < n; i++) {
            if (uint8(bits[i / 8]) & (uint8(1) << uint8(i % 8)) == 0) fields[i] = bytes32(0);
        }
        root = sha256(abi.encodePacked(progressive(fields, 0, 1), bits));
        // Field 4 alone is node 43; fields 5 on, the third level onwards, are node 11.
        branch = [fields[4], progressive(fields, 5, 16)];
        activeFields = bits;
    }

    /// A beacon block of `slot` over `stateRoot`: its root, and state_root's branch.
    function blockTree(uint64 slot, bytes32 stateRoot) internal pure returns (bytes32 root, bytes32[3] memory branch) {
        bytes32[] memory fields = new bytes32[](8);
        fields[0] = le64(slot);
        fields[1] = le64(7); // proposer_index
        fields[2] = keccak256(abi.encode("parent", slot));
        fields[3] = stateRoot;
        fields[4] = keccak256(abi.encode("body", slot));
        bytes32[] memory b;
        (root, b) = merkle(fields, 3);
        branch = [b[0], b[1], b[2]];
    }

    /// A proof of the given state fields, whose block root becomes the EIP-4788 root for `timestamp`.
    function beaconState(uint64 timestamp, bytes32 gvr, uint64 slot, bytes4 previous, bytes4 current, uint64 forkEpoch)
        internal
        returns (BridgeEscrow.BeaconProof memory p)
    {
        p.timestamp = timestamp;
        p.genesisTime = GENESIS;
        p.genesisValidatorsRoot = gvr;
        p.slot = slot;
        p.previousVersion = previous;
        p.currentVersion = current;
        p.epoch = forkEpoch;
        return prove(p, activeBits(0, 45));
    }

    /// p with the branches of a state with active-fields bits `bits`, whose block root becomes the EIP-4788 root
    /// for p.timestamp.
    function prove(BridgeEscrow.BeaconProof memory p, bytes32 bits) internal returns (BridgeEscrow.BeaconProof memory) {
        uint64 slot = p.slot;
        bytes32 stateRoot;
        (stateRoot, p.stateBranch, p.activeFields) = stateTree(p, bits);
        bytes32 blockRoot;
        (blockRoot, p.blockBranch) = blockTree(slot, stateRoot);
        BeaconRootsMock(BEACON_ROOTS).set(p.timestamp, blockRoot);
        return p;
    }

    /// The proof for `timestamp` on a chain still under Gloas: the state of the slot before the timestamp's
    /// (EIP-4788 holds the parent block's root).
    function gloasState(uint64 timestamp) internal returns (BridgeEscrow.BeaconProof memory) {
        return beaconState(timestamp, GVR, (timestamp - GENESIS) / 12 - 1, FULU, GLOAS, GLOAS_EPOCH);
    }
}
