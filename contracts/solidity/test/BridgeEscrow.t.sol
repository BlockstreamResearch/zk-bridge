// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "../contracts/BridgeEscrow.sol";
import {BeaconRootsMock, SepoliaBeacon} from "./SepoliaBeacon.sol";

interface Vm {
    struct Wallet {
        address addr;
        uint256 publicKeyX;
        uint256 publicKeyY;
        uint256 privateKey;
    }

    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function deal(address account, uint256 balance) external;
    function warp(uint256 timestamp) external;
    function etch(address target, bytes calldata code) external;
    function expectRevert(bytes4 revertData) external;
    function createWallet(uint256 privateKey) external returns (Wallet memory);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// Rejects plain ETH, but can call the escrow: the recipient kind redeemTo exists for.
contract Refuser {
    receive() external payable {
        revert("no");
    }

    function redirect(
        BridgeEscrow e,
        address payable to,
        BridgeEscrow.BurnProof calldata b,
        LiquidLightClient.BlockRef calldata r
    ) external {
        e.redeemTo(to, b, r);
    }
}

/// Accepts ETH only after spending COST gas, whatever the compiler profile: more than a fixed payout
/// stipend would allow, as a smart wallet whose receive hook writes new storage may now need on Sepolia
/// (EIP-8037 prices a new slot at 97,920 state gas). With less, it runs out of gas.
contract Hungry {
    uint256 public constant COST = 500_000;

    receive() external payable {
        uint256 start = gasleft();
        while (start - gasleft() < COST) {}
    }
}

/// Re-enters redeem once with the same burn from its receive hook and records the outcome.
contract Reenterer {
    address public escrow;
    bytes public payload;
    bool public tried;
    bool public innerOk;
    bytes4 public innerError;

    function arm(address e, bytes calldata p) external {
        (escrow, payload) = (e, p);
    }

    receive() external payable {
        if (tried) return;
        tried = true;
        (bool ok, bytes memory ret) = escrow.call(payload);
        (innerOk, innerError) = (ok, bytes4(ret));
    }
}

/// Redemption over synthetic DynaFed headers relayed into the escrow's light client by test federations,
/// and the deposit rules. Deposit admission (the window, fork proofs, the closer) is
/// BridgeEscrowAdmission.t.sol's; here every escrow proves the pinned fork right after construction, and
/// again after a test moves time past MAX_FORK_CHECK_AGE. The Elements encodings are checked against real Liquid
/// testnet transactions in ElementsParser.t.sol; the light client's own rules (epochs, DynaFed tally,
/// retired keys) in LiquidLightClient.t.sol.
contract BridgeEscrowTest is SepoliaBeacon {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    event log_named_uint(string key, uint256 val);

    uint256 constant UNIT = 10_000_000_000;
    bytes32 constant ASSET = 0x2df6418545e8293859defb9b9835cee5f139fc94157a5fbd4ffdbb4e2029472e;
    bytes32 constant LBTC = 0x499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c14;
    uint32 constant EPOCH = 1000; // Liquid testnet's dynamic_epoch_length
    uint32 constant CHECKPOINT = 1999; // the last height of epoch 1
    uint32 constant LAG = 1 days;
    // Header time of height 0, one block a minute after it; after Sepolia's Gloas activation, so a beacon
    // state proven at a header's time is under the pinned fork.
    uint32 constant TIME0 = 1_792_000_000;
    address payable constant ALICE = payable(address(0xA11CE5));
    address payable constant BOB = payable(address(0xB0B5));
    // A P2WPKH scriptPubKey: what an ordinary Liquid wallet's unconfidential segwit address pays.
    bytes constant WPKH = hex"0014" hex"1111111111111111111111111111111111111111";
    bytes32 constant G_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
    uint256 constant SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// A test federation: its signblockscript, its keys in script order and its threshold.
    struct Fed {
        bytes sbs;
        uint256[] pks;
        uint256 m;
    }

    // The default federation: 2-of-3, two confirmations, one relayed header and one 1 ETH deposit.
    BridgeEscrow escrow;
    Fed fed;

    function setUp() public {
        vm.deal(address(this), type(uint128).max); // enough for a MAX_UNITS deposit
        vm.warp(timeOf(CHECKPOINT + 1)); // the first relayed header's time
        vm.etch(BEACON_ROOTS, address(new BeaconRootsMock()).code);
        Fed memory f;
        (escrow, f) = deploy(2, 3, 0x5eed, 2);
        fed = f;
        relayEmpty(escrow, fed, 1); // deposits open once the light client is current
        escrow.deposit{value: 1 ether}(WPKH);
    }

    // ---- fixtures ----

    function le32(uint32 x) internal pure returns (bytes4) {
        return bytes4(((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | (x >> 24));
    }

    function sha256d(bytes memory b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(b)));
    }

    function compressed(Vm.Wallet memory w) internal pure returns (bytes memory) {
        return abi.encodePacked((w.publicKeyY & 1) == 1 ? bytes1(0x03) : bytes1(0x02), bytes32(w.publicKeyX));
    }

    /// An m-of-n witness script over keys seed .. seed + n - 1, with the keys' y coordinates.
    function federation(uint256 m, uint256 n, uint256 seed)
        internal
        returns (bytes memory script, uint256[] memory pks, uint256[] memory ys)
    {
        pks = new uint256[](n);
        ys = new uint256[](n);
        bytes memory body;
        for (uint256 i = 0; i < n; i++) {
            pks[i] = seed + i;
            Vm.Wallet memory w = vm.createWallet(pks[i]);
            body = bytes.concat(body, hex"21", compressed(w));
            ys[i] = w.publicKeyY;
        }
        script = bytes.concat(bytes1(uint8(0x50 + m)), body, bytes1(uint8(0x50 + n)), hex"ae");
    }

    function checkpoint(bytes memory script, uint256[] memory ys)
        internal
        pure
        returns (LiquidLightClient.Checkpoint memory)
    {
        return LiquidLightClient.Checkpoint(EPOCH, CHECKPOINT, keccak256("checkpoint block"), script, ys);
    }

    /// A 90-day window, no fork outside the pin announced, no closer, and the longest fork-check age.
    function admission() internal view returns (BridgeEscrow.Admission memory) {
        return BridgeEscrow.Admission(
            uint64(block.timestamp) + 90 days, type(uint64).max, address(0), 6 hours, GVR, GLOAS, GLOAS_EPOCH
        );
    }

    /// Proves that the beacon chain is under the pinned fork now.
    function proveFork(BridgeEscrow e) internal {
        require(e.checkFork(gloasState(uint64(block.timestamp))), "pinned");
    }

    function deploy(uint256 m, uint256 n, uint256 seed, uint32 confirmations)
        internal
        returns (BridgeEscrow e, Fed memory f)
    {
        (bytes memory script, uint256[] memory pks, uint256[] memory ys) = federation(m, n, seed);
        e = new BridgeEscrow(ASSET, confirmations, LAG, admission(), checkpoint(script, ys));
        f = Fed(abi.encodePacked(hex"0020", sha256(script)), pks, m);
        proveFork(e);
    }

    function explicitOutput(bytes32 asset, uint64 value, bytes memory spk) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"01", asset, hex"01", value, hex"00", uint8(spk.length), spk);
    }

    function confidentialOutput() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"0a",
            bytes32(uint256(1)),
            hex"09",
            bytes32(uint256(2)),
            hex"02",
            bytes32(uint256(3)),
            hex"16" hex"0014",
            bytes20(uint160(4))
        );
    }

    /// Two inputs (the first with issuance fields) and three outputs; `middle` is output 1.
    function burnTx(bytes memory middle) internal pure returns (bytes memory) {
        return bytes.concat(
            hex"0200000000" hex"02",
            bytes32(uint256(0xaa)),
            hex"01000080" hex"00" hex"ffffffff",
            bytes32(uint256(0x11)),
            bytes32(uint256(0x22)),
            hex"010000000000000005" hex"00",
            bytes32(uint256(0xbb)),
            hex"00000000" hex"03010203" hex"fdffffff",
            hex"03",
            confidentialOutput(),
            middle,
            explicitOutput(LBTC, 300, ""),
            hex"00000000"
        );
    }

    function burnFor(BridgeEscrow e, address recipient, uint64 units) internal view returns (bytes memory) {
        return burnTx(explicitOutput(ASSET, units, e.burnScriptPubKey(recipient)));
    }

    function timeOf(uint256 height) internal pure returns (uint32) {
        return uint32(TIME0 + 60 * height);
    }

    function header(bytes32 prev, bytes32 root, uint256 height, bytes memory sbs) internal pure returns (bytes memory) {
        return abi.encodePacked(
            le32(0xa0000000),
            prev,
            root,
            le32(timeOf(height)),
            le32(uint32(height)),
            hex"01",
            uint8(sbs.length),
            sbs,
            le32(1416),
            bytes32(uint256(0xe1)),
            hex"00"
        );
    }

    /// Bitcoin's transaction tree: an odd level pairs its last node with itself.
    function txTree(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32, bytes32[] memory branch) {
        uint256 depth = 0;
        for (uint256 n = leaves.length; n > 1; n = (n + 1) / 2) {
            depth++;
        }
        branch = new bytes32[](depth);
        bytes32[] memory level = leaves;
        for (uint256 d = 0; d < depth; d++) {
            branch[d] = (index ^ 1) < level.length ? level[index ^ 1] : level[index];
            bytes32[] memory next = new bytes32[]((level.length + 1) / 2);
            for (uint256 j = 0; j < next.length; j++) {
                bytes32 l = level[2 * j];
                bytes32 r = 2 * j + 1 < level.length ? level[2 * j + 1] : l;
                next[j] = sha256(abi.encodePacked(sha256(abi.encodePacked(l, r))));
            }
            level = next;
            index >>= 1;
        }
        return (level[0], branch);
    }

    /// The light client's batch tree: keccak256 leaves of the headers' Merkle roots, zero-padded to a
    /// power of two. Returns the path of leaf `index`.
    function batchPath(bytes32[] memory merkleRoots, uint256 index) internal pure returns (bytes32[] memory path) {
        uint256 size = 1;
        while (size < merkleRoots.length) size <<= 1;
        bytes32[] memory level = new bytes32[](size);
        for (uint256 i = 0; i < merkleRoots.length; i++) {
            level[i] = keccak256(abi.encodePacked(merkleRoots[i]));
        }
        uint256 depth = 0;
        for (uint256 s = size; s > 1; s >>= 1) {
            depth++;
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
    }

    function sig(uint256 pk, bytes32 h) internal pure returns (LiquidLightClient.Signature memory) {
        (, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return LiquidLightClient.Signature(r, s);
    }

    /// Signatures of keys[0 .. m-1] over the last header.
    function signTip(bytes[] memory hs, uint256[] memory pks, uint256 m)
        internal
        pure
        returns (LiquidLightClient.Signature[] memory s)
    {
        bytes32 h = sha256d(hs[hs.length - 1]);
        s = new LiquidLightClient.Signature[](m);
        for (uint256 i = 0; i < m; i++) {
            s[i] = sig(pks[i], h);
        }
    }

    /// `raw` as transaction 1 of a three-transaction block at `height`: the burn proof and the block's
    /// Merkle root. The coinbase depends on the height, so every block has its own root.
    function burnBlock(bytes memory raw, uint32 vout, uint256 height)
        internal
        pure
        returns (BridgeEscrow.BurnProof memory b, bytes32 root)
    {
        bytes32[] memory leaves = new bytes32[](3);
        (leaves[0], leaves[1], leaves[2]) =
        (keccak256(abi.encode("coinbase", height)), sha256d(raw), keccak256("another"));
        bytes32[] memory branch;
        (root, branch) = txTree(leaves, 1);
        b = BridgeEscrow.BurnProof(raw, vout, branch, 1);
    }

    /// `count` headers on top of `e`'s tip under `sbs`, the first with Merkle root `firstRoot`.
    function chain(BridgeEscrow e, bytes32 firstRoot, uint256 count, bytes memory sbs)
        internal
        view
        returns (bytes[] memory hs, bytes32[] memory roots)
    {
        hs = new bytes[](count);
        roots = new bytes32[](count);
        bytes32 prev = e.lcTipHash();
        uint256 first = uint256(e.lcTipHeight()) + 1;
        for (uint256 i = 0; i < count; i++) {
            roots[i] = i == 0 ? firstRoot : keccak256(abi.encode("filler", first + i));
            hs[i] = header(prev, roots[i], first + i, sbs);
            prev = sha256d(hs[i]);
        }
    }

    function submit(BridgeEscrow e, Fed memory f, bytes[] memory hs) internal returns (uint256) {
        return e.submitHeaders(hs, signTip(hs, f.pks, f.m), "", new uint256[](0));
    }

    /// Relays `count` headers on top of `e`'s tip, the first holding `raw`, and returns the burn proof
    /// and the reference of that first block.
    function relayBurn(BridgeEscrow e, Fed memory f, bytes memory raw, uint32 vout, uint256 count)
        internal
        returns (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref)
    {
        bytes32 root;
        (b, root) = burnBlock(raw, vout, uint256(e.lcTipHeight()) + 1);
        ref = relayRoot(e, f, root, count);
    }

    /// Relays `count` headers, the first with Merkle root `firstRoot`, and returns that block's reference.
    function relayRoot(BridgeEscrow e, Fed memory f, bytes32 firstRoot, uint256 count)
        internal
        returns (LiquidLightClient.BlockRef memory ref)
    {
        (bytes[] memory hs, bytes32[] memory roots) = chain(e, firstRoot, count, f.sbs);
        uint256 batch = submit(e, f, hs);
        ref = LiquidLightClient.BlockRef(batch, 0, batchPath(roots, 0));
    }

    /// Relays `count` headers that carry no burn.
    function relayEmpty(BridgeEscrow e, Fed memory f, uint256 count) internal {
        (bytes[] memory hs,) = chain(e, keccak256(abi.encode("no burn", e.lcTipHeight())), count, f.sbs);
        submit(e, f, hs);
    }

    function relayBurn(bytes memory raw, uint32 vout)
        internal
        returns (BridgeEscrow.BurnProof memory, LiquidLightClient.BlockRef memory)
    {
        return relayBurn(escrow, fed, raw, vout, 2);
    }

    function calldataGas(bytes memory data) internal pure returns (uint256 g) {
        for (uint256 i = 0; i < data.length; i++) {
            g += data[i] == 0 ? 4 : 16;
        }
    }

    // ---- redemption ----

    function testRedeemPaysOnce() public {
        bytes memory raw = burnFor(escrow, ALICE, 100_000);
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) = relayBurn(raw, 1);
        uint256 before = address(escrow).balance;
        escrow.redeem(ALICE, b, ref);
        require(
            ALICE.balance == 100_000 * UNIT && address(escrow).balance == before - 100_000 * UNIT,
            "paid exactly the burned units"
        );
        require(escrow.isRedeemed(sha256d(raw), 1), "nullifier set");
        vm.expectRevert(BridgeEscrow.AlreadyRedeemed.selector);
        escrow.redeem(ALICE, b, ref);
    }

    function testDuplicateRedemptionRejectedForAnyProof() public {
        bytes memory raw = burnFor(escrow, ALICE, 100_000);
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) = relayBurn(raw, 1);
        escrow.redeem(ALICE, b, ref);
        // The same transaction proven through another relayed block is still the same nullifier.
        (BridgeEscrow.BurnProof memory b2, LiquidLightClient.BlockRef memory ref2) = relayBurn(raw, 1);
        require(ref2.batch != ref.batch, "another block");
        vm.expectRevert(BridgeEscrow.AlreadyRedeemed.selector);
        escrow.redeem(ALICE, b2, ref2);
        require(ALICE.balance == 100_000 * UNIT, "paid once");
    }

    function testTwoBurnOutputsInOneTransactionAreTwoRedemptions() public {
        bytes memory spk = escrow.burnScriptPubKey(ALICE);
        bytes memory raw = bytes.concat(
            hex"0200000000" hex"01",
            bytes32(uint256(0xcc)),
            hex"00000000" hex"00" hex"ffffffff",
            hex"02",
            explicitOutput(ASSET, 100_000, spk),
            explicitOutput(ASSET, 250_000, spk),
            hex"00000000"
        );
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) = relayBurn(raw, 0);
        escrow.redeem(ALICE, b, ref);
        b.vout = 1;
        escrow.redeem(ALICE, b, ref);
        require(ALICE.balance == 350_000 * UNIT, "both outputs paid");
        vm.expectRevert(BridgeEscrow.AlreadyRedeemed.selector);
        escrow.redeem(ALICE, b, ref);
    }

    function testConfirmationsCountRelayedBlocks() public {
        bytes memory raw = burnFor(escrow, ALICE, 100_000);
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) = relayBurn(escrow, fed, raw, 1, 1);
        vm.expectRevert(BridgeEscrow.TooFewConfirmations.selector);
        escrow.redeem(ALICE, b, ref);
        relayEmpty(escrow, fed, 1); // the burn block's child
        escrow.redeem(ALICE, b, ref);
        require(ALICE.balance == 100_000 * UNIT, "paid at two confirmations");
    }

    function testBlockMustBeRelayed() public {
        bytes memory raw = burnFor(escrow, ALICE, 100_000);
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) = relayBurn(raw, 1);
        LiquidLightClient.BlockRef memory bad = LiquidLightClient.BlockRef(ref.batch + 1, 0, ref.path);
        vm.expectRevert(LiquidLightClient.UnknownBatch.selector);
        escrow.redeem(ALICE, b, bad);
        bad = LiquidLightClient.BlockRef(ref.batch, 1, ref.path); // the confirmation block holds no burn
        vm.expectRevert(LiquidLightClient.NotInBatch.selector);
        escrow.redeem(ALICE, b, bad);
        bad = LiquidLightClient.BlockRef(ref.batch, 2, ref.path); // the padding leaf
        vm.expectRevert(LiquidLightClient.BadBlockRef.selector);
        escrow.redeem(ALICE, b, bad);
        bad = LiquidLightClient.BlockRef(ref.batch, 0, new bytes32[](1));
        vm.expectRevert(LiquidLightClient.NotInBatch.selector);
        escrow.redeem(ALICE, b, bad);

        // A burn in a block nobody relayed: its Merkle root is in no batch.
        bytes memory unrelayed = burnFor(escrow, ALICE, 200_000);
        b.transaction = unrelayed;
        vm.expectRevert(LiquidLightClient.NotInBatch.selector);
        escrow.redeem(ALICE, b, ref);
    }

    function testForgedHeadersCannotBeRelayed() public {
        // Headers signed by keys outside the federation never become redeemable blocks.
        (, uint256[] memory outsiders,) = federation(2, 3, 0xbad);
        bytes memory raw = burnFor(escrow, ALICE, 100_000);
        uint256 next = uint256(escrow.lcTipHeight()) + 1;
        bytes[] memory hs = new bytes[](2);
        hs[0] = header(escrow.lcTipHash(), sha256d(raw), next, fed.sbs);
        hs[1] = header(sha256d(hs[0]), keccak256("x"), next + 1, fed.sbs);
        LiquidLightClient.Signature[] memory s = signTip(hs, outsiders, 2);
        vm.expectRevert(LiquidLightClient.BadSignature.selector);
        escrow.submitHeaders(hs, s, "", new uint256[](0));
        require(escrow.batchCount() == 1 && escrow.lcTipHeight() == next - 1, "nothing relayed beyond setUp");
    }

    function testInclusionProofMustMatch() public {
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) =
            relayBurn(burnFor(escrow, ALICE, 100_000), 1);
        b.position = 0; // the coinbase's position
        vm.expectRevert(LiquidLightClient.NotInBatch.selector);
        escrow.redeem(ALICE, b, ref);
        b.position = 1;
        b.branch[1] ^= bytes32(uint256(1));
        vm.expectRevert(LiquidLightClient.NotInBatch.selector);
        escrow.redeem(ALICE, b, ref);
        b.branch[1] ^= bytes32(uint256(1));
        b.position = 5; // does not fit a two-level branch
        vm.expectRevert(ElementsParser.BadBranch.selector);
        escrow.redeem(ALICE, b, ref);
    }

    function testBurnOutputRules() public {
        bytes memory spk = escrow.burnScriptPubKey(ALICE);
        expectRedeemRevert(burnTx(explicitOutput(LBTC, 100_000, spk)), 1, ALICE, BridgeEscrow.WrongAsset.selector);
        // Another bootstrap of the same covenants over the same escrow has another asset id; its units
        // are unbacked and must not redeem.
        bytes32 otherInstance = keccak256("asset of another bootstrap outpoint");
        expectRedeemRevert(
            burnTx(explicitOutput(otherInstance, 100_000, spk)), 1, ALICE, BridgeEscrow.WrongAsset.selector
        );
        expectRedeemRevert(burnTx(explicitOutput(ASSET, 0, spk)), 1, ALICE, BridgeEscrow.ZeroAmount.selector);
        bytes memory blinded =
            abi.encodePacked(hex"01", ASSET, hex"08", bytes32(uint256(5)), hex"00", uint8(spk.length), spk);
        expectRedeemRevert(burnTx(blinded), 1, ALICE, ElementsParser.NotExplicit.selector);
        bytes memory bare = hex"6a20" hex"0000000000000000000000000000000000000000000000000000000000000001";
        expectRedeemRevert(
            burnTx(explicitOutput(ASSET, 100_000, bare)), 1, ALICE, BridgeEscrow.WrongBurnScript.selector
        );
    }

    /// The burn is a bare OP_RETURN whose one push names, in plain bytes, the tag, the chain, this escrow and the
    /// recipient, as the interface (ui/lib/bridge.js burnTarget) and Humid's approval show it. Only that exact
    /// encoding redeems. A wallet's Burn control (Elements destroyamount) pays a bare OP_RETURN with no payload; a
    /// P2WSH script, an OP_RETURN of one 32-byte push, the same payload pushed with OP_PUSHDATA1 or followed by a
    /// byte, and payloads naming another chain, escrow or recipient are all refused.
    function testBurnIsABareOpReturnNamingTheRecipient() public {
        bytes memory spk = escrow.burnScriptPubKey(ALICE);
        bytes memory payload = abi.encodePacked("liquid-bridge-poc/burn", uint64(block.chainid), address(escrow), ALICE);
        require(
            payload.length == 70 && keccak256(spk) == keccak256(abi.encodePacked(hex"6a46", payload)),
            "OP_RETURN PUSH70 payload"
        );
        require(spk.length == 72, "the bridge burn script is exactly 72 bytes");
        require(
            escrow.BURN_TAG() == bytes22("liquid-bridge-poc/burn") && escrow.BURN_CHAIN_ID() == block.chainid,
            "the getters"
        );

        bytes32 hash = sha256("a synthetic 32-byte hash");
        bytes[7] memory refused = [
            bytes(hex"6a"), // destroyamount: no recipient
            abi.encodePacked(hex"0020", hash), // another script: P2WSH
            abi.encodePacked(hex"6a20", hash), // an OP_RETURN of one 32-byte push
            abi.encodePacked(hex"6a4c46", payload), // the same payload, pushed with OP_PUSHDATA1
            abi.encodePacked(spk, hex"00"), // a trailing push
            abi.encodePacked(hex"6a46", "liquid-bridge-poc/burn", uint64(1), address(escrow), ALICE), // another chain
            abi.encodePacked(hex"6a46", "liquid-bridge-poc/burn", uint64(block.chainid), address(escrow), BOB) // another recipient
        ];
        for (uint256 i = 0; i < refused.length; i++) {
            expectRedeemRevert(
                burnTx(explicitOutput(ASSET, 100_000, refused[i])), 1, ALICE, BridgeEscrow.WrongBurnScript.selector
            );
        }
        (BridgeEscrow other,) = deploy(2, 3, 0x5eed, 2);
        expectRedeemRevert(
            burnTx(explicitOutput(ASSET, 100_000, other.burnScriptPubKey(ALICE))),
            1,
            ALICE,
            BridgeEscrow.WrongBurnScript.selector
        );

        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) =
            relayBurn(burnTx(explicitOutput(ASSET, 100_000, spk)), 1);
        escrow.redeem(ALICE, b, ref);
        require(ALICE.balance == 100_000 * UNIT, "the bare OP_RETURN redeems");
    }

    function testBurnBindsItsRecipientAndOutput() public {
        bytes memory forBob = burnFor(escrow, BOB, 100_000);
        expectRedeemRevert(forBob, 1, ALICE, BridgeEscrow.WrongBurnScript.selector); // Bob's burn cannot pay Alice
        expectRedeemRevert(forBob, 2, BOB, BridgeEscrow.WrongAsset.selector); // the fee output
        expectRedeemRevert(forBob, 3, BOB, ElementsParser.NoSuchOutput.selector);

        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) =
            relayBurn(burnFor(escrow, ALICE, 100_000), 1);
        vm.expectRevert(BridgeEscrow.ZeroRecipient.selector);
        escrow.redeem(payable(address(0)), b, ref);
        b.transaction = new bytes(64);
        vm.expectRevert(BridgeEscrow.ShortTransaction.selector);
        escrow.redeem(ALICE, b, ref);
    }

    function expectRedeemRevert(bytes memory raw, uint32 vout, address payable recipient, bytes4 err) internal {
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) = relayBurn(raw, vout);
        vm.expectRevert(err);
        escrow.redeem(recipient, b, ref);
    }

    /// The redemption interface: ui/lib/bridge.js encodes these function signatures, finds redemptions by this
    /// Redeemed topic and explains these errors by name, so a change here must change it too. The interface builds
    /// the burn script itself and checks it against burnScriptPubKey.
    function testRedemptionSelectorsErrorsAndEvent() public pure {
        bytes32 redeemedTopic = keccak256("Redeemed(bytes32,uint32,address,address,uint64)");
        require(BridgeEscrow.Redeemed.selector == redeemedTopic, "Redeemed topic");
        string memory proofs = "(bytes,uint32,bytes32[],uint32),(uint256,uint256,bytes32[])";
        require(
            BridgeEscrow.redeem.selector == bytes4(keccak256(bytes(string.concat("redeem(address,", proofs, ")")))),
            "redeem"
        );
        require(
            BridgeEscrow.redeemTo.selector == bytes4(keccak256(bytes(string.concat("redeemTo(address,", proofs, ")")))),
            "redeemTo"
        );
        require(
            BridgeEscrow.burnScriptPubKey.selector == bytes4(keccak256("burnScriptPubKey(address)")), "burnScriptPubKey"
        );
        require(BridgeEscrow.isRedeemed.selector == bytes4(keccak256("isRedeemed(bytes32,uint32)")), "isRedeemed");
        bytes4[9] memory errors = [
            BridgeEscrow.ZeroRecipient.selector,
            BridgeEscrow.ShortTransaction.selector,
            BridgeEscrow.AlreadyRedeemed.selector,
            BridgeEscrow.WrongAsset.selector,
            BridgeEscrow.ZeroAmount.selector,
            BridgeEscrow.WrongBurnScript.selector,
            BridgeEscrow.TooFewConfirmations.selector,
            BridgeEscrow.Insolvent.selector,
            BridgeEscrow.PayoutFailed.selector
        ];
        string[9] memory names = [
            "ZeroRecipient()",
            "ShortTransaction()",
            "AlreadyRedeemed()",
            "WrongAsset()",
            "ZeroAmount()",
            "WrongBurnScript()",
            "TooFewConfirmations()",
            "Insolvent()",
            "PayoutFailed()"
        ];
        for (uint256 i = 0; i < errors.length; i++) {
            require(errors[i] == bytes4(keccak256(bytes(names[i]))), names[i]); // the interface explains these by name
        }
    }

    // ---- conservation and payout ----

    function testConservationAndInsolvency() public {
        // 1 ether (100,000,000 units) deposited in setUp.
        uint256 redeemedUnits;
        for (uint256 i = 0; i < 3; i++) {
            uint64 units = uint64(100_000 * (i + 1));
            (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) =
                relayBurn(burnFor(escrow, ALICE, units), 1);
            escrow.redeem(ALICE, b, ref);
            redeemedUnits += units;
            require(
                address(escrow).balance == (100_000_000 - redeemedUnits) * UNIT,
                "balance = (deposited - redeemed) units"
            );
        }
        // A burn larger than the remaining deposits can only exist if the block signers fail (L1); the
        // redemption then reverts and leaves no nullifier behind.
        (BridgeEscrow.BurnProof memory big, LiquidLightClient.BlockRef memory bref) =
            relayBurn(burnFor(escrow, ALICE, 100_000_000), 1);
        vm.expectRevert(BridgeEscrow.Insolvent.selector);
        escrow.redeem(ALICE, big, bref);
        require(!escrow.isRedeemed(sha256d(big.transaction), 1), "no nullifier after an insolvent redemption");
    }

    /// A recipient that refuses plain ETH: a redemption reverts and leaves the burn unspent, and the
    /// recipient itself redeems to an address it names. Nobody else can redirect its burn.
    function testRefusingRecipientRedeemsToAnotherAddress() public {
        Refuser r = new Refuser();
        address payable rr = payable(address(r));
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) =
            relayBurn(burnFor(escrow, rr, 100_000), 1);
        vm.expectRevert(BridgeEscrow.PayoutFailed.selector);
        escrow.redeem(rr, b, ref);
        require(!escrow.isRedeemed(sha256d(b.transaction), 1), "the burn is still unspent");
        vm.expectRevert(BridgeEscrow.WrongBurnScript.selector); // this test contract is not the burn's recipient
        escrow.redeemTo(BOB, b, ref);
        vm.expectRevert(BridgeEscrow.ZeroRecipient.selector);
        r.redirect(escrow, payable(address(0)), b, ref);
        vm.expectRevert(BridgeEscrow.PayoutFailed.selector); // to itself: refused again, nothing spent
        r.redirect(escrow, rr, b, ref);
        vm.recordLogs();
        r.redirect(escrow, BOB, b, ref);
        require(
            BOB.balance == 100_000 * UNIT && rr.balance == 0 && escrow.isRedeemed(sha256d(b.transaction), 1),
            "paid where the recipient said"
        );
        Vm.Log[] memory logs = vm.getRecordedLogs();
        require(
            logs.length == 1 && logs[0].topics[0] == keccak256("Redeemed(bytes32,uint32,address,address,uint64)"),
            "the interface's Redeemed topic"
        );
        require(
            logs[0].topics[1] == sha256d(b.transaction) && logs[0].topics[2] == bytes32(uint256(uint160(address(rr)))),
            "Redeemed names the burn and its recipient"
        );
        (uint32 vout, address to, uint64 units) = abi.decode(logs[0].data, (uint32, address, uint64));
        require(vout == 1 && to == BOB && units == 100_000, "and where the ETH went");
        vm.expectRevert(BridgeEscrow.AlreadyRedeemed.selector);
        r.redirect(escrow, BOB, b, ref);
    }

    /// No fixed payout gas: a recipient whose receive hook needs 500,000 gas is paid in full once the
    /// submitter sends enough, and with too little the whole redemption fails and nothing is spent. A
    /// fixed stipend, such as 200,000, would turn this willing recipient into a refusing one, and whether
    /// a stipend suffices depends on the fork's gas schedule.
    function testGasHungryRecipientIsPaidOrNothingHappens() public {
        address payable h = payable(address(new Hungry()));
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) =
            relayBurn(burnFor(escrow, h, 100_000), 1);
        (bool ok, bytes memory ret) =
            address(escrow).call{gas: 400_000}(abi.encodeCall(BridgeEscrow.redeem, (h, b, ref)));
        require(
            !ok && bytes4(ret) == BridgeEscrow.PayoutFailed.selector,
            "the payout ran short and took the redemption with it"
        );
        require(!escrow.isRedeemed(sha256d(b.transaction), 1) && h.balance == 0, "nothing spent");
        escrow.redeem(h, b, ref);
        require(
            h.balance == 100_000 * UNIT && escrow.isRedeemed(sha256d(b.transaction), 1), "paid in full with enough gas"
        );
    }

    function testReentrancyCannotRepeatAPayout() public {
        Reenterer r = new Reenterer();
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) =
            relayBurn(burnFor(escrow, address(r), 100_000), 1);
        r.arm(address(escrow), abi.encodeCall(BridgeEscrow.redeem, (payable(address(r)), b, ref)));
        escrow.redeem(payable(address(r)), b, ref);
        require(
            r.tried() && !r.innerOk() && r.innerError() == BridgeEscrow.AlreadyRedeemed.selector, "inner redeem refused"
        );
        require(address(r).balance == 100_000 * UNIT, "paid once");
    }

    // ---- deposits ----

    function testDepositsOpenOnlyWhileTheLightClientIsCurrent() public {
        (BridgeEscrow e, Fed memory f) = deploy(1, 1, 0x4444, 2);
        require(!e.depositsOpen(), "closed before anything is relayed");
        vm.expectRevert(BridgeDeposits.DepositsClosed.selector);
        e.deposit{value: 0.001 ether}(WPKH);
        relayEmpty(e, f, 1);
        uint256 tipTime = e.lcTipTime();
        require(tipTime == timeOf(CHECKPOINT + 1), "tip time is the header's");
        vm.warp(tipTime + LAG);
        proveFork(e); // a day on, the deployment's proof is older than MAX_FORK_CHECK_AGE
        require(e.depositsOpen(), "open at the edge of the lag");
        e.deposit{value: 0.001 ether}(WPKH);
        vm.warp(tipTime + LAG + 1);
        require(!e.depositsOpen(), "closed once the light client trails by more than the lag");
        vm.expectRevert(BridgeDeposits.DepositsClosed.selector);
        e.deposit{value: 0.001 ether}(WPKH);
        // Redemptions are never gated: a relayed burn redeems while deposits are closed.
        (BridgeEscrow.BurnProof memory b, LiquidLightClient.BlockRef memory ref) =
            relayBurn(e, f, burnFor(e, ALICE, 100_000), 1, 2);
        require(e.depositsOpen(), "relaying newer headers reopens deposits");
        vm.warp(e.lcTipTime() + LAG + 1);
        e.redeem(ALICE, b, ref);
        require(ALICE.balance == 100_000 * UNIT, "redeemed while deposits are closed");
    }

    function testDepositRecipientScripts() public {
        bytes20 h = bytes20(uint160(0x2222));
        bytes[5] memory ok = [
            abi.encodePacked(hex"76a914", h, hex"88ac"), // P2PKH
            abi.encodePacked(hex"a914", h, hex"87"), // P2SH
            abi.encodePacked(hex"0014", h), // P2WPKH
            abi.encodePacked(hex"0020", bytes32(uint256(0x3333))), // P2WSH
            abi.encodePacked(hex"5120", G_X) // P2TR, the generator's x
        ];
        for (uint256 i = 0; i < ok.length; i++) {
            require(escrow.recipientOf(ok[i]) == sha256(ok[i]), "the recipient is the script's SHA-256");
            escrow.deposit{value: 0.001 ether}(ok[i]);
        }
        bytes[9] memory bad = [
            bytes(""),
            abi.encodePacked(hex"6a20", bytes32(0)), // OP_RETURN: a burn
            abi.encodePacked(hex"5220", G_X), // witness v2: spendable by anyone today
            abi.encodePacked(hex"5120", bytes32(SECP_P)), // not a field element
            abi.encodePacked(hex"5120", bytes32(offCurveX())), // no curve point
            abi.encodePacked(hex"0014", h, hex"00"), // P2WPKH with a stray byte
            abi.encodePacked(hex"a914", h, hex"88"), // P2SH without OP_EQUAL
            abi.encodePacked(hex"76a914", h, hex"88ad"), // P2PKH ending in OP_CHECKSIGVERIFY
            abi.encodePacked(G_X) // a bare x-only key, not a script
        ];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(BridgeDeposits.BadRecipientScript.selector);
            escrow.deposit{value: 0.001 ether}(bad[i]);
        }
    }

    /// The smallest x with no point on secp256k1, by Euler's criterion through the modexp precompile.
    function offCurveX() internal view returns (uint256 x) {
        for (x = 1;; x++) {
            uint256 rhs = addmod(mulmod(mulmod(x, x, SECP_P), x, SECP_P), 7, SECP_P);
            (bool ok, bytes memory r) = address(0x05)
                .staticcall(abi.encodePacked(uint256(32), uint256(32), uint256(32), rhs, (SECP_P - 1) / 2, SECP_P));
            require(ok, "modexp");
            if (uint256(bytes32(r)) != 1) return x;
        }
    }

    function testDepositAmountRulesAndEvent() public {
        vm.expectRevert(BridgeDeposits.BadDepositAmount.selector);
        escrow.deposit{value: 0.001 ether + 1}(WPKH);
        vm.expectRevert(BridgeDeposits.BadDepositAmount.selector);
        escrow.deposit{value: 99_999 * UNIT}(WPKH);
        vm.expectRevert(BridgeDeposits.BadDepositAmount.selector);
        escrow.deposit{value: (2_100_000_000_000_000 + 1) * UNIT}(WPKH);
        escrow.deposit{value: 2_100_000_000_000_000 * UNIT}(WPKH); // exactly MAX_UNITS
        vm.recordLogs();
        uint64 index = escrow.deposit{value: 123_456 * UNIT}(WPKH);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1 && logs[0].topics[1] == bytes32(uint256(index)), "one Deposit event");
        (uint64 units, bytes32 recipient, bytes32 leaf, bytes32 acc, bytes memory script) =
            abi.decode(logs[0].data, (uint64, bytes32, bytes32, bytes32, bytes));
        require(
            units == 123_456 && recipient == sha256(WPKH) && keccak256(script) == keccak256(WPKH),
            "the script a claimer needs"
        );
        require(leaf == escrow.leafOf(index, units, recipient) && acc == escrow.accumulator(), "commitments");
    }

    /// The incremental tree equals a full-tree construction, and slot 0 is the accumulator.
    function testDepositsKeepTheAccumulatorRules() public {
        bytes32[] memory leaves = new bytes32[](9);
        leaves[0] = escrow.leafOf(0, 100_000_000, sha256(WPKH)); // setUp's deposit
        for (uint256 k = 1; k < 9; k++) {
            bytes memory script = abi.encodePacked(hex"0014", bytes20(uint160(k)));
            uint64 index = escrow.deposit{value: (100_000 + k) * UNIT}(script);
            leaves[k] = escrow.leafOf(index, uint64(100_000 + k), sha256(script));
        }
        bytes32[33] memory zero;
        for (uint256 h = 0; h < 32; h++) {
            zero[h + 1] = sha256(abi.encodePacked(zero[h], zero[h]));
        }
        bytes32[] memory level = leaves;
        for (uint256 h = 0; h < 32; h++) {
            bytes32[] memory up = new bytes32[]((level.length + 1) / 2);
            for (uint256 j = 0; j < up.length; j++) {
                up[j] = sha256(abi.encodePacked(level[2 * j], 2 * j + 1 < level.length ? level[2 * j + 1] : zero[h]));
            }
            level = up;
        }
        require(escrow.treeRoot() == level[0] && escrow.depositCount() == 9, "incremental root = full tree");
        require(escrow.accumulator() == sha256(abi.encodePacked(level[0], uint64(9))), "accumulator rule");
        require(vm.load(address(escrow), bytes32(0)) == escrow.accumulator(), "slot 0 is the accumulator");
        require(
            escrow.DOMAIN() == sha256(abi.encodePacked("liquid-bridge-poc/deposit", block.chainid, address(escrow))),
            "deposit domain"
        );
    }

    // ---- gas ----
    // Only the contract call sits inside each measured window; headers and signatures are built before
    // it. Execution gas of an internal call, so excluding the 21,000 base and calldata costs. Measured
    // under foundry.toml's evm_version (prague), not current Sepolia's Glamsterdam schedule, which
    // reprices state access (EIP-8038) and charges new storage and code separately as state gas
    // (EIP-8037): these figures are not Sepolia costs.

    /// Builds and signs `count` headers on `e`'s tip, the first with Merkle root `firstRoot`, and logs
    /// the gas of submitHeaders alone. Returns the batch's Merkle roots.
    function measuredRelay(BridgeEscrow e, Fed memory f, bytes32 firstRoot, uint256 count, string memory name)
        internal
        returns (bytes32[] memory roots)
    {
        bytes[] memory hs;
        (hs, roots) = chain(e, firstRoot, count, f.sbs);
        LiquidLightClient.Signature[] memory s = signTip(hs, f.pks, f.m);
        uint256 g = gasleft();
        e.submitHeaders(hs, s, "", new uint256[](0));
        emit log_named_uint(string.concat("submitHeaders execution gas, ", name), g - gasleft());
    }

    function relayAndRedeemGas(BridgeEscrow e, Fed memory f, string memory name) internal {
        relayEmpty(e, f, 1);
        e.deposit{value: 1 ether}(WPKH);
        (BridgeEscrow.BurnProof memory b, bytes32 root) =
            burnBlock(burnFor(e, ALICE, 100_000), 1, uint256(e.lcTipHeight()) + 1);
        bytes32[] memory roots = measuredRelay(e, f, root, 2, string.concat(name, ", 2 headers"));
        LiquidLightClient.BlockRef memory ref = LiquidLightClient.BlockRef(e.batchCount() - 1, 0, batchPath(roots, 0));
        uint256 g = gasleft();
        e.redeem(ALICE, b, ref);
        emit log_named_uint(string.concat("redeem execution gas, ", name), g - gasleft());
        emit log_named_uint(
            "redeem calldata gas (16/4 per byte)", calldataGas(abi.encodeCall(BridgeEscrow.redeem, (ALICE, b, ref)))
        );
        require(ALICE.balance == 100_000 * UNIT, "paid");
    }

    function testOneOfOneGas() public {
        // 1-of-1 multisig: the shape Liquid testnet's signed headers carry (block 2,664,829).
        (BridgeEscrow e, Fed memory f) = deploy(1, 1, 0x1111, 2);
        relayAndRedeemGas(e, f, "1-of-1");
    }

    function testElevenOfFifteenGas() public {
        // 11-of-15: the shape of Liquid mainnet's 513-byte witness script.
        (BridgeEscrow e, Fed memory f) = deploy(11, 15, 0x7777, 2);
        require(e.signingThreshold() == 11 && e.federation().length == 15, "shape");
        relayAndRedeemGas(e, f, "11-of-15");
    }

    function testHundredHeaderBatchGas() public {
        measuredRelay(escrow, fed, keccak256("no burn"), 100, "2-of-3, 100 headers");
        require(escrow.lcTipHeight() == CHECKPOINT + 101 && escrow.batchCount() == 2, "tip");
    }

    function testDepositGas() public {
        uint256 g = gasleft();
        escrow.deposit{value: 0.001 ether}(abi.encodePacked(hex"5120", G_X));
        emit log_named_uint("deposit execution gas, P2TR recipient (key check)", g - gasleft());
        g = gasleft();
        escrow.deposit{value: 0.001 ether}(WPKH);
        emit log_named_uint("deposit execution gas, P2WPKH recipient", g - gasleft());
    }

    // ---- deployment ----

    function testConstructorRejectsBadParameters() public {
        (bytes memory script,, uint256[] memory ys) = federation(1, 1, 0x3333);
        BridgeEscrow.Admission memory a = admission(); // its own bounds are BridgeEscrowAdmission.t.sol's
        vm.expectRevert(BridgeEscrow.ZeroAsset.selector);
        new BridgeEscrow(bytes32(0), 2, LAG, a, checkpoint(script, ys));
        vm.expectRevert(BridgeEscrow.ZeroConfirmations.selector);
        new BridgeEscrow(ASSET, 0, LAG, a, checkpoint(script, ys));
        vm.expectRevert(BridgeEscrow.BadRelayLag.selector);
        new BridgeEscrow(ASSET, 2, 59 minutes, a, checkpoint(script, ys));
        vm.expectRevert(BridgeEscrow.BadRelayLag.selector);
        new BridgeEscrow(ASSET, 2, 31 days, a, checkpoint(script, ys));
        vm.expectRevert(LiquidLightClient.BadCheckpoint.selector); // not the last height of an epoch
        new BridgeEscrow(
            ASSET, 2, LAG, a, LiquidLightClient.Checkpoint(EPOCH, CHECKPOINT + 1, keccak256("c"), script, ys)
        );
        vm.expectRevert(LiquidLightClient.BadEpochLength.selector);
        new BridgeEscrow(ASSET, 2, LAG, a, LiquidLightClient.Checkpoint(1001, 1000, keccak256("c"), script, ys));
        uint256[] memory wrongY = new uint256[](1);
        wrongY[0] = ys[0] ^ 1;
        vm.expectRevert(LiquidLightClient.BadKey.selector);
        new BridgeEscrow(ASSET, 2, LAG, a, checkpoint(script, wrongY));
        vm.expectRevert(LiquidLightClient.BadWitnessScript.selector);
        new BridgeEscrow(ASSET, 2, LAG, a, checkpoint(bytes.concat(script, hex"00"), ys));
    }
}
