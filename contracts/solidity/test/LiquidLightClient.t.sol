// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "../contracts/LiquidLightClient.sol";

interface Vm {
    struct Wallet {
        address addr;
        uint256 publicKeyX;
        uint256 publicKeyY;
        uint256 privateKey;
    }

    function expectRevert(bytes4 revertData) external;
    function createWallet(uint256 privateKey) external returns (Wallet memory);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function exists(string calldata path) external view returns (bool);
    function readFile(string calldata path) external view returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonBytesArray(string calldata json, string calldata key) external pure returns (bytes[] memory);
    function parseJsonBytes32Array(string calldata json, string calldata key) external pure returns (bytes32[] memory);
}

/// Exposes the internal block lookup and the parser's transaction Merkle rule.
contract ClientHarness is LiquidLightClient {
    constructor(Checkpoint memory cp) LiquidLightClient(cp) {}

    function blockHeight(BlockRef calldata ref, bytes32 merkleRoot) external view returns (uint32) {
        return _blockHeight(ref, merkleRoot);
    }

    function txMerkleRoot(bytes32 txid, bytes32[] calldata branch, uint256 position) external pure returns (bytes32) {
        return ElementsParser.merkleRoot(txid, branch, position);
    }
}

/// A block-signing federation of test keys: OP_m <keys> OP_n OP_CHECKMULTISIG, as Liquid uses.
struct Fed {
    bytes script; // the witness script
    bytes sbs; // its signblockscript, P2WSH(script)
    uint256[] ys;
    uint256[] pks;
    uint256 m;
}

/// The arguments of one submitHeaders call, built before any vm.expectRevert: building them calls
/// the cheatcode and the SHA-256 precompile, which must not be the call a revert is expected from.
struct Call {
    bytes[] hs;
    LiquidLightClient.Signature[] sigs;
    bytes script;
    uint256[] ys;
}

contract LiquidLightClientTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    event log_named_uint(string key, uint256 val);

    string constant FIXTURE = "test/fixtures/liquid-testnet-headers.json";
    uint32 constant L = 10; // regtest's default epoch length; T = 8
    uint32 constant CHECKPOINT = 9; // last height of epoch 0
    bytes32 constant CHECKPOINT_HASH = keccak256("checkpoint block");
    uint256 constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    Fed k1;
    Fed k2;
    Fed k3;
    ClientHarness client;

    function setUp() public {
        k1 = federation(1, 1, 0x1001);
        k2 = federation(1, 1, 0x2002);
        k3 = federation(2, 3, 0x3003);
        client = deploy(k1);
    }

    // ---- fixtures ----

    function le32(uint32 x) internal pure returns (bytes4) {
        return bytes4(((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | (x >> 24));
    }

    function sha256d(bytes memory b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(b)));
    }

    function federation(uint256 m, uint256 n, uint256 seed) internal returns (Fed memory f) {
        f.pks = new uint256[](n);
        f.ys = new uint256[](n);
        bytes memory body;
        for (uint256 i = 0; i < n; i++) {
            f.pks[i] = seed + i;
            Vm.Wallet memory w = vm.createWallet(f.pks[i]);
            bytes1 prefix = (w.publicKeyY & 1) == 1 ? bytes1(0x03) : bytes1(0x02);
            body = bytes.concat(body, hex"21", prefix, bytes32(w.publicKeyX));
            f.ys[i] = w.publicKeyY;
        }
        f.script = bytes.concat(bytes1(uint8(0x50 + m)), body, bytes1(uint8(0x50 + n)), hex"ae");
        f.sbs = abi.encodePacked(hex"0020", sha256(f.script));
        f.m = m;
    }

    function checkpoint(bytes memory script, uint256[] memory ys)
        internal
        pure
        returns (LiquidLightClient.Checkpoint memory)
    {
        return LiquidLightClient.Checkpoint(L, CHECKPOINT, CHECKPOINT_HASH, script, ys);
    }

    function deploy(Fed memory f) internal returns (ClientHarness) {
        return new ClientHarness(checkpoint(f.script, f.ys));
    }

    function compact(bytes memory sbs) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"01", uint8(sbs.length), sbs, le32(1416), bytes32(uint256(0xe1)));
    }

    /// A full entry with empty fedpeg program and script and no extension space.
    function full(bytes memory sbs) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"02", uint8(sbs.length), sbs, le32(1416), hex"00", hex"00", hex"00");
    }

    function merkleRootAt(uint256 height) internal pure returns (bytes32) {
        return keccak256(abi.encode("transactions", height));
    }

    function header(bytes32 prev, uint256 height, bytes memory sbs, bytes memory proposed)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            le32(0xa0000000),
            prev,
            merkleRootAt(height),
            le32(1_760_000_000 + uint32(height)),
            le32(uint32(height)),
            compact(sbs),
            proposed
        );
    }

    /// `count` headers from height `from`, the first a child of `prev`; header i proposes
    /// proposals[i] when i < proposals.length, and nothing otherwise.
    function chain(bytes32 prev, uint256 from, uint256 count, bytes memory sbs, bytes[] memory proposals)
        internal
        pure
        returns (bytes[] memory hs)
    {
        hs = new bytes[](count);
        for (uint256 i = 0; i < count; i++) {
            hs[i] = header(prev, from + i, sbs, i < proposals.length ? proposals[i] : bytes(hex"00"));
            prev = sha256d(hs[i]);
        }
    }

    function plain(bytes32 prev, uint256 from, uint256 count, bytes memory sbs) internal pure returns (bytes[] memory) {
        return chain(prev, from, count, sbs, new bytes[](0));
    }

    function votes(bytes memory entry, uint256 count) internal pure returns (bytes[] memory p) {
        p = new bytes[](count);
        for (uint256 i = 0; i < count; i++) {
            p[i] = entry;
        }
    }

    function sig(uint256 pk, bytes32 h) internal pure returns (LiquidLightClient.Signature memory) {
        (, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return LiquidLightClient.Signature(r, s);
    }

    /// Signatures of the first f.m keys over the last header.
    function signTip(bytes[] memory hs, Fed memory f) internal pure returns (LiquidLightClient.Signature[] memory s) {
        bytes32 h = sha256d(hs[hs.length - 1]);
        s = new LiquidLightClient.Signature[](f.m);
        for (uint256 i = 0; i < f.m; i++) {
            s[i] = sig(f.pks[i], h);
        }
    }

    /// `hs` signed by `signer`, without a witness script.
    function signed(bytes[] memory hs, Fed memory signer) internal pure returns (Call memory) {
        return Call(hs, signTip(hs, signer), "", new uint256[](0));
    }

    /// `hs` signed by `signer`, carrying `next`'s witness script and key ys.
    function rotating(bytes[] memory hs, Fed memory signer, Fed memory next) internal pure returns (Call memory) {
        return Call(hs, signTip(hs, signer), next.script, next.ys);
    }

    /// Exactly one external call, so it can follow vm.expectRevert.
    function send(ClientHarness c, Call memory x) internal returns (uint256) {
        return c.submitHeaders(x.hs, x.sigs, x.script, x.ys);
    }

    /// The stored tip hash and the next height.
    function tip(ClientHarness c) internal view returns (bytes32, uint256) {
        return (c.lcTipHash(), uint256(c.lcTipHeight()) + 1);
    }

    /// The contract's batch tree over `merkleRoots`, and the path of `index`.
    function batchTree(bytes32[] memory merkleRoots, uint256 index)
        internal
        pure
        returns (bytes32, bytes32[] memory path)
    {
        uint256 size = 1;
        uint256 depth = 0;
        while (size < merkleRoots.length) (size, depth) = (size << 1, depth + 1);
        bytes32[] memory level = new bytes32[](size);
        for (uint256 i = 0; i < merkleRoots.length; i++) {
            level[i] = keccak256(abi.encodePacked(merkleRoots[i]));
        }
        path = new bytes32[](depth);
        for (uint256 d = 0; d < depth; d++) {
            path[d] = level[index ^ 1];
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 j = 0; j < next.length; j++) {
                next[j] = keccak256(abi.encodePacked(level[2 * j], level[2 * j + 1]));
            }
            level = next;
            index >>= 1;
        }
        return (level[0], path);
    }

    function word(bytes memory b, uint256 at) internal pure returns (bytes32 w) {
        require(at + 32 <= b.length, "word out of range");
        assembly {
            w := mload(add(add(b, 32), at))
        }
    }

    /// Each header's transaction Merkle root, bytes 36 .. 68.
    function merkleRootsOf(bytes[] memory hs) internal pure returns (bytes32[] memory roots) {
        roots = new bytes32[](hs.length);
        for (uint256 i = 0; i < hs.length; i++) {
            roots[i] = word(hs[i], 36);
        }
    }

    function slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = from; i < to; i++) {
            out[i - from] = b[i];
        }
    }

    // ---- relaying ----

    function testBatchesExtendTheCheckpointAndCommitEveryBlock() public {
        require(
            client.epoch() == 1 && client.lcTipHeight() == CHECKPOINT && client.lcTipHash() == CHECKPOINT_HASH,
            "checkpoint"
        );
        require(client.signblockscriptHash() == keccak256(k1.sbs) && client.signingThreshold() == 1, "checkpoint keys");
        require(
            client.federation().length == 1 && client.federation()[0] == vm.createWallet(k1.pks[0]).addr, "federation"
        );

        bytes[] memory a = plain(CHECKPOINT_HASH, 10, 5, k1.sbs);
        require(send(client, signed(a, k1)) == 0, "batch 0");
        bytes[] memory b = plain(sha256d(a[4]), 15, 3, k1.sbs);
        require(send(client, signed(b, k1)) == 1, "batch 1");
        require(
            client.lcTipHeight() == 17 && client.lcTipHash() == sha256d(b[2]) && client.lcTipTime() == 1_760_000_017,
            "tip"
        );
        require(
            client.batchCount() == 2 && client.batchAt(1).firstHeight == 15 && client.batchAt(1).count == 3, "batches"
        );

        bytes32[] memory roots = merkleRootsOf(a);
        for (uint256 i = 0; i < a.length; i++) {
            (bytes32 r, bytes32[] memory path) = batchTree(roots, i);
            require(r == client.batchAt(0).root, "batch root");
            require(client.blockHeight(LiquidLightClient.BlockRef(0, i, path), roots[i]) == 10 + i, "height");
        }
        (, bytes32[] memory p1) = batchTree(merkleRootsOf(b), 2);
        require(client.blockHeight(LiquidLightClient.BlockRef(1, 2, p1), merkleRootAt(17)) == 17, "batch 1 height");
    }

    function testBlockRefsOpenOnlyStoredBlocks() public {
        bytes[] memory a = plain(CHECKPOINT_HASH, 10, 5, k1.sbs);
        send(client, signed(a, k1));
        bytes32[] memory roots = merkleRootsOf(a);
        (, bytes32[] memory path) = batchTree(roots, 3);

        vm.expectRevert(LiquidLightClient.UnknownBatch.selector);
        client.blockHeight(LiquidLightClient.BlockRef(1, 3, path), roots[3]);
        // Five leaves pad to eight: indices 5 .. 7 are padding, not blocks.
        vm.expectRevert(LiquidLightClient.BadBlockRef.selector);
        client.blockHeight(LiquidLightClient.BlockRef(0, 5, path), bytes32(0));
        vm.expectRevert(LiquidLightClient.BadBlockRef.selector);
        client.blockHeight(LiquidLightClient.BlockRef(0, 3, new bytes32[](2)), roots[3]);
        vm.expectRevert(LiquidLightClient.NotInBatch.selector);
        client.blockHeight(LiquidLightClient.BlockRef(0, 3, path), roots[2]);
        vm.expectRevert(LiquidLightClient.NotInBatch.selector);
        client.blockHeight(LiquidLightClient.BlockRef(0, 2, path), roots[3]);
        path[0] ^= bytes32(uint256(1));
        vm.expectRevert(LiquidLightClient.NotInBatch.selector);
        client.blockHeight(LiquidLightClient.BlockRef(0, 3, path), roots[3]);
    }

    function testMalformedBatchesAreRejected() public {
        Call memory x = Call(new bytes[](0), new LiquidLightClient.Signature[](0), "", new uint256[](0));
        vm.expectRevert(LiquidLightClient.EmptyBatch.selector);
        send(client, x);

        x = signed(plain(keccak256("elsewhere"), 10, 3, k1.sbs), k1); // not the checkpoint's child
        vm.expectRevert(LiquidLightClient.BrokenChain.selector);
        send(client, x);
        x = signed(plain(CHECKPOINT_HASH, 11, 3, k1.sbs), k1); // skips height 10
        vm.expectRevert(LiquidLightClient.BrokenChain.selector);
        send(client, x);
        bytes[] memory gap = plain(CHECKPOINT_HASH, 10, 3, k1.sbs);
        gap[2] = header(sha256d(gap[0]), 12, k1.sbs, hex"00"); // a child of height 10, not 11
        x = signed(gap, k1);
        vm.expectRevert(LiquidLightClient.BrokenChain.selector);
        send(client, x);

        x = signed(plain(CHECKPOINT_HASH, 10, 11, k1.sbs), k1); // heights 10 .. 20
        vm.expectRevert(LiquidLightClient.CrossesEpoch.selector);
        send(client, x);
        x = rotating(plain(CHECKPOINT_HASH, 10, 3, k1.sbs), k1, k1); // no key change is due
        vm.expectRevert(LiquidLightClient.UnexpectedWitnessScript.selector);
        send(client, x);

        bytes[] memory ok = plain(CHECKPOINT_HASH, 10, 3, k1.sbs);
        x = Call(ok, new LiquidLightClient.Signature[](0), "", new uint256[](0));
        vm.expectRevert(LiquidLightClient.WrongSignatureCount.selector);
        send(client, x);
        x = signed(ok, k2); // another key
        vm.expectRevert(LiquidLightClient.BadSignature.selector);
        send(client, x);
        x = signed(ok, k1);
        x.sigs[0].s = bytes32(uint256(x.sigs[0].s) ^ 1);
        vm.expectRevert(LiquidLightClient.BadSignature.selector);
        send(client, x);
        x = signed(plain(CHECKPOINT_HASH, 10, 3, k2.sbs), k1); // the right key, another script
        vm.expectRevert(LiquidLightClient.WrongSignblockscript.selector);
        send(client, x);

        send(client, signed(ok, k1));
        require(client.lcTipHeight() == 12, "the honest batch after the failures");
    }

    /// The contract never verifies a header against the script that header carries.
    function testHeadersSignedUnderTheirOwnScriptAreRejected() public {
        bytes[] memory forged = plain(CHECKPOINT_HASH, 10, 3, k2.sbs);
        Call memory x = signed(forged, k2);
        vm.expectRevert(LiquidLightClient.WrongSignblockscript.selector);
        send(client, x);
        // Supplying the forger's witness script does not help outside a decided key change.
        x = rotating(forged, k2, k2);
        vm.expectRevert(LiquidLightClient.UnexpectedWitnessScript.selector);
        send(client, x);
    }

    // ---- DynaFed key changes ----

    /// Epoch 1 (heights 10 .. 19) votes 8 of 10 for k2: epoch 2 must be signed by k2, never by k1.
    function testKeyChangeFollowsFourFifthsOfTheEpoch() public {
        send(client, signed(chain(CHECKPOINT_HASH, 10, 10, k1.sbs, votes(full(k2.sbs), 8)), k1));
        require(client.nonNullVotes() == 8 && client.winnerSignblockscriptHash() == keccak256(k2.sbs), "tally");
        (bytes32 prev, uint256 next) = tip(client);
        require(next == 20, "epoch 1 covered");

        bytes[] memory retired = plain(prev, next, 3, k1.sbs);
        bytes[] memory rotated = plain(prev, next, 3, k2.sbs);
        Call memory x = signed(retired, k1);
        vm.expectRevert(LiquidLightClient.MissingWitnessScript.selector);
        send(client, x);
        x = rotating(retired, k1, k2); // the old script after the change
        vm.expectRevert(LiquidLightClient.WrongSignblockscript.selector);
        send(client, x);
        x = rotating(rotated, k2, k3);
        vm.expectRevert(LiquidLightClient.WrongWitnessScript.selector);
        send(client, x);
        x = rotating(rotated, k1, k2); // the new script, the old key
        vm.expectRevert(LiquidLightClient.BadSignature.selector);
        send(client, x);

        send(client, rotating(rotated, k2, k2));
        require(client.epoch() == 2 && client.signblockscriptHash() == keccak256(k2.sbs), "epoch 2 keys");
        require(client.nonNullVotes() == 0 && client.winnerSignblockscriptHash() == bytes32(0), "tally reset");
        require(client.federation()[0] == vm.createWallet(k2.pks[0]).addr, "federation replaced");

        // The retired key cannot extend the chain at any later height.
        (prev, next) = tip(client);
        x = signed(plain(prev, next, 2, k1.sbs), k1);
        vm.expectRevert(LiquidLightClient.WrongSignblockscript.selector);
        send(client, x);
        x = signed(plain(prev, next, 2, k2.sbs), k1);
        vm.expectRevert(LiquidLightClient.BadSignature.selector);
        send(client, x);
        send(client, signed(plain(prev, next, 2, k2.sbs), k2));
    }

    function testVotesAccumulateAcrossBatchesWithinAnEpoch() public {
        bytes[] memory first = chain(CHECKPOINT_HASH, 10, 6, k1.sbs, votes(full(k3.sbs), 6));
        send(client, signed(first, k1));
        send(client, signed(chain(sha256d(first[5]), 16, 4, k1.sbs, votes(full(k3.sbs), 2)), k1));
        require(client.winnerSignblockscriptHash() == keccak256(k3.sbs), "8 votes over two batches");
        (bytes32 prev, uint256 next) = tip(client);
        // A 2-of-3 federation takes over; its first batch carries its witness script and key ys.
        send(client, rotating(plain(prev, next, 4, k3.sbs), k3, k3));
        require(client.signingThreshold() == 2 && client.federation().length == 3, "2-of-3");
    }

    function testSevenVotesKeepTheKeys() public {
        send(client, signed(chain(CHECKPOINT_HASH, 10, 10, k1.sbs, votes(full(k2.sbs), 7)), k1));
        require(client.winnerSignblockscriptHash() == bytes32(0), "no winner");
        (bytes32 prev, uint256 next) = tip(client);
        Call memory x = rotating(plain(prev, next, 2, k2.sbs), k2, k2);
        vm.expectRevert(LiquidLightClient.UnexpectedWitnessScript.selector);
        send(client, x);
        x = signed(plain(prev, next, 2, k2.sbs), k1);
        vm.expectRevert(LiquidLightClient.WrongSignblockscript.selector);
        send(client, x);
        send(client, signed(plain(prev, next, 2, k1.sbs), k1));
        require(client.epoch() == 2 && client.signblockscriptHash() == keccak256(k1.sbs), "unchanged");
    }

    /// Votes do not carry over: 4 + 4 votes in consecutive epochs change nothing.
    function testVotesDoNotCarryAcrossEpochs() public {
        bytes[] memory hs = chain(CHECKPOINT_HASH, 10, 10, k1.sbs, votes(full(k2.sbs), 4));
        send(client, signed(hs, k1));
        hs = chain(sha256d(hs[9]), 20, 10, k1.sbs, votes(full(k2.sbs), 4));
        send(client, signed(hs, k1));
        require(client.epoch() == 2 && client.nonNullVotes() == 4, "epoch 2 tally");
        send(client, signed(plain(sha256d(hs[9]), 30, 1, k1.sbs), k1));
        require(client.epoch() == 3 && client.signblockscriptHash() == keccak256(k1.sbs), "still k1");
    }

    /// Eight non-null votes without one serialization reaching 8: Elements may or may not change keys
    /// (equal parameters in two encodings do; different parameters do not), so the client stops.
    /// This is the liveness cost of tallying serializations; no transition is followed wrongly.
    function testUndecidableTallyFailsClosed() public {
        bytes[] memory mixed = new bytes[](8);
        for (uint256 i = 0; i < 8; i++) {
            mixed[i] = i < 4 ? full(k2.sbs) : compact(k2.sbs);
        }
        send(client, signed(chain(CHECKPOINT_HASH, 10, 10, k1.sbs, mixed), k1));
        require(client.nonNullVotes() == 8 && client.winnerSignblockscriptHash() == bytes32(0), "split tally");
        (bytes32 prev, uint256 next) = tip(client);
        Call memory x = signed(plain(prev, next, 1, k1.sbs), k1);
        vm.expectRevert(LiquidLightClient.AmbiguousTally.selector);
        send(client, x);
        x = rotating(plain(prev, next, 1, k2.sbs), k2, k2);
        vm.expectRevert(LiquidLightClient.AmbiguousTally.selector);
        send(client, x);

        ClientHarness other = deploy(k1);
        for (uint256 i = 0; i < 8; i++) {
            mixed[i] = i < 4 ? full(k2.sbs) : full(k3.sbs);
        }
        send(other, signed(chain(CHECKPOINT_HASH, 10, 10, k1.sbs, mixed), k1));
        (prev, next) = tip(other);
        x = signed(plain(prev, next, 1, k1.sbs), k1);
        vm.expectRevert(LiquidLightClient.AmbiguousTally.selector);
        send(other, x);
    }

    /// The boundary of assumption L3. While epoch 1 is not fully relayed, its keys sign for its unrelayed
    /// heights, even if Liquid has meanwhile retired them: a fork of heights 12 .. 19 signed by k1 is
    /// accepted with transaction roots of its choosing, and its 8 votes hand epoch 2 to the forger's keys.
    /// This pins what the client trusts; no check can remove it (see the contract notes on L3).
    function testUnrelayedHeightsOfAnEpochTrustThatEpochsKeys() public {
        bytes[] memory honest = plain(CHECKPOINT_HASH, 10, 2, k1.sbs);
        send(client, signed(honest, k1));
        bytes32 fakeRoot = keccak256("a block holding a burn that never happened");
        bytes[] memory fork = new bytes[](8);
        bytes32 prev = sha256d(honest[1]);
        for (uint256 i = 0; i < 8; i++) {
            fork[i] = abi.encodePacked(
                le32(0xa0000000),
                prev,
                fakeRoot,
                le32(1_760_000_000),
                le32(uint32(12 + i)),
                compact(k1.sbs),
                full(k3.sbs)
            );
            prev = sha256d(fork[i]);
        }
        uint256 forged = send(client, signed(fork, k1));
        require(client.winnerSignblockscriptHash() == keccak256(k3.sbs), "the fork's votes decide epoch 2");
        (, bytes32[] memory path) = batchTree(merkleRootsOf(fork), 0);
        require(
            client.blockHeight(LiquidLightClient.BlockRef(forged, 0, path), fakeRoot) == 12,
            "a forged block opens like any covered block"
        );
        send(client, rotating(plain(prev, 20, 1, k3.sbs), k3, k3));
        require(
            client.epoch() == 2 && client.signblockscriptHash() == keccak256(k3.sbs), "the forger's keys sign epoch 2"
        );
    }

    /// A winning proposal that keeps the signblockscript (a fedpeg-only change, say) changes no keys.
    function testWinnerWithTheSameSigningScriptKeepsTheKeys() public {
        bytes memory sameSigners =
            abi.encodePacked(hex"02", uint8(k1.sbs.length), k1.sbs, le32(1416), hex"0151", hex"00", hex"00");
        send(client, signed(chain(CHECKPOINT_HASH, 10, 10, k1.sbs, votes(sameSigners, 8)), k1));
        require(client.winnerSignblockscriptHash() == keccak256(k1.sbs), "the winner keeps k1's script");
        (bytes32 prev, uint256 next) = tip(client);
        Call memory x = rotating(plain(prev, next, 1, k1.sbs), k1, k1);
        vm.expectRevert(LiquidLightClient.UnexpectedWitnessScript.selector);
        send(client, x);
        send(client, signed(plain(prev, next, 1, k1.sbs), k1));
        require(client.epoch() == 2 && client.signblockscriptHash() == keccak256(k1.sbs), "same keys in epoch 2");
        require(client.winnerSignblockscriptHash() == bytes32(0), "tally reset");
    }

    // ---- signatures ----

    function testMultisigNeedsDistinctKeysInScriptOrder() public {
        ClientHarness c = deploy(k3);
        bytes[] memory hs = plain(CHECKPOINT_HASH, 10, 2, k3.sbs);
        bytes32 h = sha256d(hs[1]);
        Call memory x = Call(hs, new LiquidLightClient.Signature[](2), "", new uint256[](0));
        (x.sigs[0], x.sigs[1]) = (sig(k3.pks[1], h), sig(k3.pks[0], h));
        vm.expectRevert(LiquidLightClient.BadSignature.selector); // out of order
        send(c, x);
        (x.sigs[0], x.sigs[1]) = (sig(k3.pks[0], h), sig(k3.pks[0], h));
        vm.expectRevert(LiquidLightClient.BadSignature.selector); // one key twice
        send(c, x);
        Call memory one = Call(hs, new LiquidLightClient.Signature[](1), "", new uint256[](0));
        one.sigs[0] = sig(k3.pks[0], h);
        vm.expectRevert(LiquidLightClient.WrongSignatureCount.selector);
        send(c, one);
        Call memory three = Call(hs, new LiquidLightClient.Signature[](3), "", new uint256[](0));
        (three.sigs[0], three.sigs[1], three.sigs[2]) = (sig(k3.pks[0], h), sig(k3.pks[1], h), sig(k3.pks[2], h));
        vm.expectRevert(LiquidLightClient.WrongSignatureCount.selector);
        send(c, three);
        (x.sigs[0], x.sigs[1]) = (sig(k3.pks[0], h), sig(k3.pks[2], h)); // keys 0 and 2, skipping key 1
        send(c, x);
    }

    // ---- checkpoint ----

    function testCheckpointShapeIsConstrained() public {
        bytes memory s = k1.script;
        uint256[] memory ys = k1.ys;
        LiquidLightClient.Checkpoint memory cp = LiquidLightClient.Checkpoint(0, CHECKPOINT, CHECKPOINT_HASH, s, ys);
        vm.expectRevert(LiquidLightClient.BadEpochLength.selector);
        new ClientHarness(cp);
        cp = LiquidLightClient.Checkpoint(12, 11, CHECKPOINT_HASH, s, ys); // (4 * 12) / 5 = 9, 12 - 12 / 5 = 10
        vm.expectRevert(LiquidLightClient.BadEpochLength.selector);
        new ClientHarness(cp);
        cp = LiquidLightClient.Checkpoint(L, 10, CHECKPOINT_HASH, s, ys); // not the last height of an epoch
        vm.expectRevert(LiquidLightClient.BadCheckpoint.selector);
        new ClientHarness(cp);
        cp = LiquidLightClient.Checkpoint(L, CHECKPOINT, bytes32(0), s, ys);
        vm.expectRevert(LiquidLightClient.BadCheckpoint.selector);
        new ClientHarness(cp);

        cp = checkpoint(bytes.concat(hex"52", slice(s, 1, s.length)), ys); // OP_2 of one key
        vm.expectRevert(LiquidLightClient.BadWitnessScript.selector);
        new ClientHarness(cp);
        cp = checkpoint(slice(s, 0, s.length - 1), ys); // truncated
        vm.expectRevert(LiquidLightClient.BadWitnessScript.selector);
        new ClientHarness(cp);
        cp = checkpoint(bytes.concat(slice(s, 0, s.length - 1), hex"af"), ys); // OP_CHECKMULTISIGVERIFY
        vm.expectRevert(LiquidLightClient.BadWitnessScript.selector);
        new ClientHarness(cp);

        cp = checkpoint(s, new uint256[](0));
        vm.expectRevert(LiquidLightClient.BadKey.selector);
        new ClientHarness(cp);
        uint256[] memory y = new uint256[](1);
        y[0] = ys[0] ^ 2; // off the curve
        cp = checkpoint(s, y);
        vm.expectRevert(LiquidLightClient.BadKey.selector);
        new ClientHarness(cp);
        y = new uint256[](1);
        y[0] = P - ys[0]; // on the curve, the parity the prefix rules out
        cp = checkpoint(s, y);
        vm.expectRevert(LiquidLightClient.BadKey.selector);
        new ClientHarness(cp);
    }

    // ---- gas ----
    // Under foundry.toml's evm_version (prague), not current Sepolia's Glamsterdam schedule (EIP-8037
    // state gas, EIP-8038 access prices): local figures, not Sepolia costs.

    /// Gas of one 1-of-1 batch of `count` compact headers at Liquid testnet's epoch length: the
    /// execution gas of the call alone, and the calldata gas of its input at 16 / 4 gas per nonzero /
    /// zero byte (the EIP-7623 floor, 40 / 10, can exceed it for such calldata).
    function measure(uint256 count) internal {
        ClientHarness c = new ClientHarness(LiquidLightClient.Checkpoint(1000, 999, CHECKPOINT_HASH, k1.script, k1.ys));
        bytes[] memory hs = plain(CHECKPOINT_HASH, 1000, count, k1.sbs);
        bytes memory data = abi.encodeCall(c.submitHeaders, (hs, signTip(hs, k1), "", new uint256[](0)));
        callAndMeasure(address(c), data, string.concat("synthetic 1-of-1 batch of ", vm.toString(count), " headers: "));
        require(c.lcTipHeight() == 999 + count, "synthetic batch accepted");
    }

    /// Calls `target` with `data`, requires success, and logs the call's execution gas and its input's
    /// calldata gas.
    function callAndMeasure(address target, bytes memory data, string memory label) internal {
        uint256 g = gasleft();
        (bool ok,) = target.call(data);
        g -= gasleft();
        require(ok, string.concat(label, "the call reverted"));
        (uint256 cd, uint256 floor) = calldataGas(data);
        emit log_named_uint(string.concat(label, "execution gas"), g);
        emit log_named_uint(string.concat(label, "calldata gas"), cd);
        emit log_named_uint(string.concat(label, "EIP-7623 floor calldata gas"), floor);
        emit log_named_uint(string.concat(label, "calldata bytes"), data.length);
    }

    function calldataGas(bytes memory data) internal pure returns (uint256 standard, uint256 floor) {
        for (uint256 i = 0; i < data.length; i++) {
            (standard, floor) = data[i] == 0 ? (standard + 4, floor + 10) : (standard + 16, floor + 40);
        }
    }

    function testGasOfSyntheticBatches() public {
        measure(1);
        measure(100);
        measure(1000);
    }

    // ---- real Liquid testnet headers ----

    /// Public Liquid testnet headers written by tools/liquid-relay/relay.py `fixture`: a checkpoint at
    /// the end of an epoch, the following consecutive hash-form headers cut from the signed headers
    /// Esplora serves, and the real 1-of-1 signblock witness signature of each batch tip.
    function testRealLiquidTestnetHeaders() public {
        require(
            vm.exists(FIXTURE),
            "missing fixture: run tools/liquid-relay/relay.py fixture (tools/liquid-relay/README.md)"
        );
        string memory json = vm.readFile(FIXTURE);
        ClientHarness c = new ClientHarness(realCheckpoint(json));
        uint256 batches = vm.parseJsonUint(json, ".batchCount");
        require(batches > 0, "fixture has no batch");
        for (uint256 b = 0; b < batches; b++) {
            submitRealBatch(c, json, b);
        }
        realTransaction(c, json);
    }

    /// Fixture batch `b`: its tampered forms are rejected first (batch 0), then it is accepted and the tip is
    /// the block Esplora served at its last height.
    function submitRealBatch(ClientHarness c, string memory json, uint256 b) internal {
        string memory at = string.concat(".batches[", vm.toString(b), "]");
        bytes[] memory hs = vm.parseJsonBytesArray(json, string.concat(at, ".headers"));
        LiquidLightClient.Signature[] memory s = new LiquidLightClient.Signature[](1);
        s[0].r = vm.parseJsonBytes32(json, string.concat(at, ".sigR"));
        s[0].s = vm.parseJsonBytes32(json, string.concat(at, ".sigS"));
        if (b == 0) rejectTampered(c, hs, s);
        bytes memory data = abi.encodeCall(c.submitHeaders, (hs, s, "", new uint256[](0)));
        callAndMeasure(
            address(c), data, string.concat("real batch ", vm.toString(b), " of ", vm.toString(hs.length), " headers: ")
        );
        require(
            c.lcTipHash() == vm.parseJsonBytes32(json, string.concat(at, ".tipHash")),
            "tip hash = the block id Esplora serves"
        );
        uint256 last = vm.parseJsonUint(json, string.concat(at, ".firstHeight")) + hs.length - 1;
        require(c.lcTipHeight() == last, "tip height");
    }

    function realCheckpoint(string memory json) internal pure returns (LiquidLightClient.Checkpoint memory cp) {
        bytes32[] memory ys = vm.parseJsonBytes32Array(json, ".keyY");
        cp.keyY = new uint256[](ys.length);
        for (uint256 i = 0; i < ys.length; i++) {
            cp.keyY[i] = uint256(ys[i]);
        }
        cp.epochLength = uint32(vm.parseJsonUint(json, ".epochLength"));
        cp.height = uint32(vm.parseJsonUint(json, ".checkpointHeight"));
        cp.hash = vm.parseJsonBytes32(json, ".checkpointHash");
        cp.witnessScript = vm.parseJsonBytes(json, ".witnessScript");
    }

    /// Each mutation of the real first batch fails at its own rule.
    function rejectTampered(ClientHarness c, bytes[] memory hs, LiquidLightClient.Signature[] memory s) internal {
        uint256 last = hs.length - 1;
        bytes memory honest = hs[last];
        bytes[] memory forged = new bytes[](hs.length);
        for (uint256 i = 0; i < hs.length; i++) {
            forged[i] = hs[i];
        }
        forged[last] = bytes.concat(honest);
        forged[last][40] = forged[last][40] ^ bytes1(0x01); // the tip's transaction Merkle root
        Call memory x = Call(forged, s, "", new uint256[](0));
        vm.expectRevert(LiquidLightClient.BadSignature.selector);
        send(c, x);
        if (last > 0) {
            forged[last] = honest;
            forged[0] = bytes.concat(hs[0]);
            forged[0][40] = forged[0][40] ^ bytes1(0x01); // the first header's root: its child's link breaks
            x = Call(forged, s, "", new uint256[](0));
            vm.expectRevert(LiquidLightClient.BrokenChain.selector);
            send(c, x);
        }
        LiquidLightClient.Signature[] memory bad = new LiquidLightClient.Signature[](1);
        bad[0] = LiquidLightClient.Signature(s[0].r, bytes32(uint256(s[0].s) ^ 1));
        x = Call(hs, bad, "", new uint256[](0));
        vm.expectRevert(LiquidLightClient.BadSignature.selector);
        send(c, x);
    }

    /// A real confirmed transaction is in a block the client covers: Esplora's Merkle branch reaches
    /// that header's root, and the batch commitment opens to the transaction's height.
    function realTransaction(ClientHarness c, string memory json) internal view {
        uint256 height = vm.parseJsonUint(json, ".tx.height");
        bytes32 root = c.txMerkleRoot(
            vm.parseJsonBytes32(json, ".tx.txid"),
            vm.parseJsonBytes32Array(json, ".tx.branch"),
            vm.parseJsonUint(json, ".tx.position")
        );
        uint256 batches = vm.parseJsonUint(json, ".batchCount");
        for (uint256 b = 0; b < batches; b++) {
            if (openRealBlock(c, json, b, height, root)) return;
        }
        revert("the fixture transaction is outside the fixture batches");
    }

    /// False if `height` is not in fixture batch `b`; otherwise checks that the transaction's Merkle root is
    /// that header's, and that the stored batch opens to `height`.
    function openRealBlock(ClientHarness c, string memory json, uint256 b, uint256 height, bytes32 root)
        internal
        view
        returns (bool)
    {
        string memory at = string.concat(".batches[", vm.toString(b), "]");
        uint256 first = vm.parseJsonUint(json, string.concat(at, ".firstHeight"));
        bytes32[] memory roots = merkleRootsOf(vm.parseJsonBytesArray(json, string.concat(at, ".headers")));
        if (height < first || height >= first + roots.length) return false;
        require(roots[height - first] == root, "Esplora's branch reaches the header's Merkle root");
        (, bytes32[] memory path) = batchTree(roots, height - first);
        require(c.blockHeight(LiquidLightClient.BlockRef(b, height - first, path), root) == height, "covered height");
        return true;
    }
}
