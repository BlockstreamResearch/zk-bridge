// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "../contracts/ElementsParser.sol";

interface Vm {
    function expectRevert(bytes4 revertData) external;
}

/// External entry points, so tests can expect the library's reverts.
contract ParserHarness {
    function txid(bytes calldata raw) external pure returns (bytes32) {
        return ElementsParser.sha256d(raw);
    }

    function output(bytes calldata raw, uint256 vout) external pure returns (ElementsParser.ExplicitOutput memory) {
        return ElementsParser.explicitOutput(raw, vout);
    }

    function header(bytes calldata h) external pure returns (ElementsParser.Header memory) {
        return ElementsParser.header(h);
    }

    function root(bytes32 leaf, bytes32[] calldata branch, uint256 position) external pure returns (bytes32) {
        return ElementsParser.merkleRoot(leaf, branch, position);
    }
}

/// Public Liquid testnet transactions, byte-identical to the raw transactions any node or explorer serves,
/// cut to their txid form: version, flags byte 0, inputs, outputs, locktime.
library LiquidTestnetTxs {
    // Claim 63371b48...124f, block 2,664,802: a reissuance input, a confidential token output, an
    // explicit 100,000-unit mint to P2TR 78dabc6d... and an explicit 2,000-sat fee.
    bytes internal constant CLAIM = hex"0200000000"
        hex"02dd6ae27ab29f5de51feb0acce584e48236fd3110daa3025160a6a215226171d80000008000fffffffff0fe2f4baa7e72c653443e23486f7674fb299e5bed1b9d6fb991b3e7290d17fa35ff122acbdf6e351e83b46e6d90f9ad4896fdbe9938883ad11cb6748c0f13da0100000000000186a000e660ad14a3c4c87025f2dc82a512e26df14f55a43cfa0d141c5a3e1aea25b0090000000000ffffffff030a4a79eb790664415855cd8c108125a3532f697509ae204359e0d222398f176c45096173b4d8ea6a0b4e775884a3018d03ce90568c009e8e9183d8d40f2abd0b2e230022512066dda0bc4f8b061faeab227ef775d415453dfc0e1212cbd59c4d36a2f5adda56012df6418545e8293859defb9b9835cee5f139fc94157a5fbd4ffdbb4e2029472e0100000000000186a00022512078dabc6d84b09f040140897d20a39b3a36b8cd4c558bd1af51bbc464394a9f2101499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000007d0000000000000";
    bytes32 internal constant CLAIM_TXID_DISPLAY = 0x63371b487d1140e07c192d3d0855f48061531970748480baab86ee7bd7ea124f;

    // Fee split 09b025ea...60e6: one P2WPKH input, three explicit L-BTC outputs.
    bytes internal constant FEE_SPLIT = hex"0200000000"
        hex"014176d754e3ba12c51ff21b8fbea75baa5ecca8d237cb36370e0fcf479e6110370100000000ffffffff0301499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000007d000160014afea9b1b6c5a9bd559c12d8a40633f88055acad201499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000119a400160014afea9b1b6c5a9bd559c12d8a40633f88055acad201499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c1401000000000000012c000000000000";
    bytes32 internal constant FEE_SPLIT_TXID_DISPLAY =
        0x09b025ea1a3e5a1c140dfa3ca4554ff16de212a582dcf22570c8c4a314ad60e6;

    // Bootstrap 6c9d6523...11a7: a new issuance (null amount, one explicit inflation key) and a
    // confidential token output.
    bytes internal constant BOOTSTRAP = hex"0200000000"
        hex"0184e569d9750e6266b1afca811c61f1f4fe6d0588748dacb9be7083e45ac2d5cf0000008000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001030befe50ce30ade8f45d4cd5cbe8a27af87b0e4f3c8b0f44248ed461e41d4cb85ef096173b4d8ea6a0b4e775884a3018d03ce90568c009e8e9183d8d40f2abd0b2e2300225120de4e00598a4bd7fc9173e68448147b4492d2aa3e8b5599be54e92405d95b661f01499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000182b800160014afea9b1b6c5a9bd559c12d8a40633f88055acad201499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c140100000000000003e8000000000000";
    bytes32 internal constant BOOTSTRAP_TXID_DISPLAY =
        0x6c9d6523f33912f763bcb35103d638c3300cab840e1202cf3b0f15d0f0c811a7;

    bytes32 internal constant BRIDGE_ASSET = 0x2df6418545e8293859defb9b9835cee5f139fc94157a5fbd4ffdbb4e2029472e;
    bytes32 internal constant TESTNET_LBTC = 0x499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c14;
}

contract ElementsParserTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    ParserHarness p;

    function setUp() public {
        p = new ParserHarness();
    }

    // Display hex is the reverse of the internal byte order.
    function rev(bytes32 x) internal pure returns (bytes32 r) {
        for (uint256 i = 0; i < 32; i++) {
            r |= bytes32(uint256(uint8(x[i])) << (8 * i));
        }
    }

    function sha256dPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(abi.encodePacked(a, b))));
    }

    function le32(uint32 x) internal pure returns (bytes4) {
        return bytes4(((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | (x >> 24));
    }

    function slice(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = from; i < to; i++) {
            out[i - from] = b[i];
        }
    }

    // ---- transactions ----

    function testRealTxidsMatchTheChain() public view {
        require(rev(p.txid(LiquidTestnetTxs.CLAIM)) == LiquidTestnetTxs.CLAIM_TXID_DISPLAY, "claim txid");
        require(rev(p.txid(LiquidTestnetTxs.FEE_SPLIT)) == LiquidTestnetTxs.FEE_SPLIT_TXID_DISPLAY, "fee split txid");
        require(rev(p.txid(LiquidTestnetTxs.BOOTSTRAP)) == LiquidTestnetTxs.BOOTSTRAP_TXID_DISPLAY, "bootstrap txid");
    }

    function testRealClaimOutputs() public {
        ElementsParser.ExplicitOutput memory mint = p.output(LiquidTestnetTxs.CLAIM, 1);
        require(mint.asset == LiquidTestnetTxs.BRIDGE_ASSET && mint.value == 100_000, "mint asset and value");
        require(
            mint.scriptHash == keccak256(hex"512078dabc6d84b09f040140897d20a39b3a36b8cd4c558bd1af51bbc464394a9f21"),
            "mint script"
        );
        ElementsParser.ExplicitOutput memory fee = p.output(LiquidTestnetTxs.CLAIM, 2);
        require(
            fee.asset == LiquidTestnetTxs.TESTNET_LBTC && fee.value == 2_000 && fee.scriptHash == keccak256(""),
            "fee output"
        );
        vm.expectRevert(ElementsParser.NotExplicit.selector); // the token output is confidential
        p.output(LiquidTestnetTxs.CLAIM, 0);
        vm.expectRevert(ElementsParser.NoSuchOutput.selector);
        p.output(LiquidTestnetTxs.CLAIM, 3);
    }

    function testRealIssuanceAndSegwitOutputs() public {
        ElementsParser.ExplicitOutput memory change = p.output(LiquidTestnetTxs.BOOTSTRAP, 1);
        require(change.asset == LiquidTestnetTxs.TESTNET_LBTC && change.value == 99_000, "bootstrap change");
        require(change.scriptHash == keccak256(hex"0014afea9b1b6c5a9bd559c12d8a40633f88055acad2"), "P2WPKH script");
        require(p.output(LiquidTestnetTxs.BOOTSTRAP, 2).value == 1_000, "bootstrap fee");
        vm.expectRevert(ElementsParser.NotExplicit.selector);
        p.output(LiquidTestnetTxs.BOOTSTRAP, 0);
        require(p.output(LiquidTestnetTxs.FEE_SPLIT, 1).value == 72_100, "fee split change");
    }

    function testMalformedTransactionsRevert() public {
        bytes memory raw = LiquidTestnetTxs.CLAIM;
        bytes memory bad = bytes.concat(raw);
        bad[4] = 0x01; // the witness serialization is not the txid form
        vm.expectRevert(ElementsParser.WitnessFlag.selector);
        p.output(bad, 1);

        vm.expectRevert(ElementsParser.TrailingBytes.selector);
        p.output(bytes.concat(raw, hex"00"), 1);

        vm.expectRevert(ElementsParser.Truncated.selector);
        p.output(slice(raw, 0, raw.length - 1), 1);

        // The same input count 2, CompactSize-encoded in three bytes.
        vm.expectRevert(ElementsParser.NonCanonicalSize.selector);
        p.output(bytes.concat(slice(raw, 0, 5), hex"fd0200", slice(raw, 6, raw.length)), 1);

        vm.expectRevert(ElementsParser.NoInputs.selector);
        p.output(hex"0200000000000100000000", 0);

        // Output 1's asset prefix 0x05 is no Elements encoding; reading output 2 must skip it.
        bad = bytes.concat(raw);
        // version and flags (5), vin count (1), input 0 with issuance (41 + 74), input 1 (41), vout count (1), output 0 (102)
        uint256 out1 = 5 + 1 + 115 + 41 + 1 + 102;
        require(bad[out1] == 0x01, "output 1 offset");
        bad[out1] = 0x05;
        vm.expectRevert(ElementsParser.BadPrefix.selector);
        p.output(bad, 2);
    }

    // ---- headers ----

    function compact(bytes memory script) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"01", uint8(script.length), script, le32(1416), bytes32(uint256(0xe1)));
    }

    function full(bytes memory script) internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"02",
            uint8(script.length),
            script,
            le32(1416),
            hex"03" hex"aabbcc",
            hex"02" hex"5151",
            hex"02" hex"01" hex"ff" hex"00"
        );
    }

    function dynafed(uint32 version, bytes memory current, bytes memory proposed) internal pure returns (bytes memory) {
        return abi.encodePacked(
            le32(version),
            bytes32(uint256(0xbeef)),
            bytes32(uint256(0x7007)),
            le32(1_760_000_000),
            le32(2_664_802),
            current,
            proposed
        );
    }

    function testHeaderCompactAndFullParams() public view {
        bytes memory script = hex"0020" hex"1111111111111111111111111111111111111111111111111111111111111111";
        bytes memory h = dynafed(0xa0000000, compact(script), hex"00");
        ElementsParser.Header memory x = p.header(h);
        require(
            x.prev == bytes32(uint256(0xbeef)) && x.merkleRoot == bytes32(uint256(0x7007)) && x.height == 2_664_802,
            "fields"
        );
        require(x.signblockscriptHash == keccak256(script), "signblockscript");
        require(x.hash == sha256(abi.encodePacked(sha256(h))), "hash");
        require(
            x.time == 1_760_000_000 && x.proposalHash == 0 && x.proposedSignblockscriptHash == 0, "time, no proposal"
        );
        // An epoch-start header carries full current params; a vote carries non-null proposed params.
        ElementsParser.Header memory y = p.header(dynafed(0xa0000000, full(script), compact(hex"0020")));
        require(y.signblockscriptHash == keccak256(script) && y.height == 2_664_802, "full params");
        require(
            y.proposalHash == keccak256(compact(hex"0020")) && y.proposedSignblockscriptHash == keccak256(hex"0020"),
            "proposal"
        );
    }

    function testMalformedHeadersRevert() public {
        bytes memory script = hex"00201111111111111111111111111111111111111111111111111111111111111111";
        vm.expectRevert(ElementsParser.NotDynafed.selector);
        p.header(dynafed(0x20000000, compact(script), hex"00"));
        vm.expectRevert(ElementsParser.NullCurrentParams.selector);
        p.header(dynafed(0xa0000000, hex"00", hex"00"));
        vm.expectRevert(ElementsParser.BadParamsType.selector);
        p.header(dynafed(0xa0000000, hex"03", hex"00"));
        bytes memory h = dynafed(0xa0000000, compact(script), hex"00");
        vm.expectRevert(ElementsParser.Truncated.selector);
        p.header(slice(h, 0, h.length - 1));
        // A header as nodes and explorers serve it, with its signblock witness, must be cut to the
        // hash form first.
        vm.expectRevert(ElementsParser.TrailingBytes.selector);
        p.header(bytes.concat(h, hex"03" hex"00" hex"01aa" hex"01bb"));
    }

    // ---- Merkle branches ----

    // Bitcoin's tree: an odd level pairs its last node with itself.
    function tree(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32, bytes32[] memory branch) {
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
                next[j] = sha256dPair(l, 2 * j + 1 < level.length ? level[2 * j + 1] : l);
            }
            level = next;
            index >>= 1;
        }
        return (level[0], branch);
    }

    function testMerkleBranchesOfEveryPosition() public view {
        for (uint256 n = 1; n <= 7; n++) {
            bytes32[] memory leaves = new bytes32[](n);
            for (uint256 i = 0; i < n; i++) {
                leaves[i] = keccak256(abi.encode(n, i));
            }
            for (uint256 i = 0; i < n; i++) {
                (bytes32 r, bytes32[] memory branch) = tree(leaves, i);
                require(p.root(leaves[i], branch, i) == r, "branch");
                if (n > 1) {
                    // The last leaf of an odd level is paired with itself, so both sides give the same
                    // root there (CVE-2012-2459's duplicate). Redemption nullifiers do not use positions.
                    bool duplicated = branch[0] == leaves[i];
                    require((p.root(leaves[i], branch, i ^ 1) == r) == duplicated, "other side");
                    branch[0] ^= bytes32(uint256(1));
                    require(p.root(leaves[i], branch, i) != r, "wrong sibling");
                }
            }
        }
    }

    function testMerklePositionMustFitTheBranch() public {
        bytes32[] memory branch = new bytes32[](2);
        vm.expectRevert(ElementsParser.BadBranch.selector);
        p.root(bytes32(0), branch, 4);
        vm.expectRevert(ElementsParser.BadBranch.selector);
        p.root(bytes32(0), new bytes32[](33), 0);
    }
}
