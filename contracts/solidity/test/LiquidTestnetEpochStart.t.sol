// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {LiquidLightClient} from "../contracts/LiquidLightClient.sol";
import {ElementsParser} from "../contracts/ElementsParser.sol";

/// Independent public-chain check: Liquid testnet block 2664000, the first of its epoch, with its block-signing
/// witness script, signature and its two txids, as any Liquid testnet node or explorer serves them. The constants
/// are inline, so this does not depend on tools/liquid-relay/relay.py, which writes the fixture of
/// LiquidLightClient.t.sol `testRealLiquidTestnetHeaders`.
contract EpochStartHarness is LiquidLightClient {
    constructor(Checkpoint memory cp) LiquidLightClient(cp) {}

    function blockHeight(BlockRef calldata ref, bytes32 merkleRoot) external view returns (uint32) {
        return _blockHeight(ref, merkleRoot);
    }

    function txMerkleRoot(bytes32 txid, bytes32[] calldata branch, uint256 position) external pure returns (bytes32) {
        return ElementsParser.merkleRoot(txid, branch, position);
    }
}

contract LiquidTestnetEpochStartTest {
    bytes constant HEADER =
        hex"000000a04054cb0dd4c42b4725aac4b85b1cb0d86738b09bc06789ade85088fc382c2e61e56e1c9fefbc09a6343654e694071b79bada50986eea3fba469f489439a4e1c3c9c1d26a40a6280002220020e9e4117540f7f23b3edd7c2cad660a17fb33c7959b8c37cf61d92b189133929a9600000017a91472c44f957fc011d97e3406667dca5b1c930c4026870151014202fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f02fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f00";
    bytes constant SCRIPT = hex"51210217e403ddb181872c32a0cd468c710040b2f53d8cac69f18dad07985ee37e9a7151ae";
    bytes32 constant PREV = 0x4054cb0dd4c42b4725aac4b85b1cb0d86738b09bc06789ade85088fc382c2e61;
    bytes32 constant R = 0x4b36a7485d57747c837f3d481966a896ac5ab610f9c99acce7cd1ef452d9e3db;
    bytes32 constant S = 0x71d9ccd8f1598bb17f348f198168b82627da564fc1e79a7cf15d8f99cb33f8e5;
    uint256 constant KEY_Y = 0x6b3e7c7a50a5a173b577290cb7ee976809b87df20db40875ee7acdd79b81b642;
    bytes32 constant MERKLE_ROOT = 0xe56e1c9fefbc09a6343654e694071b79bada50986eea3fba469f489439a4e1c3;
    bytes32 constant TX0 = 0xb2dae7aa28be5f317cf4aa9df10961702fe1417dc08d3e8e48000ceb3fccb80c;
    bytes32 constant TX1 = 0x989593cacc39b6713cb569245bce0a5dc3dcc62a95a1d6e40732992e561b38b7;

    function fixture()
        internal
        returns (EpochStartHarness c, bytes[] memory headers, LiquidLightClient.Signature[] memory sigs)
    {
        uint256[] memory ys = new uint256[](1);
        ys[0] = KEY_Y;
        c = new EpochStartHarness(LiquidLightClient.Checkpoint(1000, 2663999, PREV, SCRIPT, ys));
        headers = new bytes[](1);
        headers[0] = HEADER;
        sigs = new LiquidLightClient.Signature[](1);
        sigs[0] = LiquidLightClient.Signature(R, S);
    }

    function testRealEpochStartHeaderAndWitness() public {
        (EpochStartHarness c, bytes[] memory hs, LiquidLightClient.Signature[] memory sigs) = fixture();
        bytes memory changed = bytes.concat(hs[0]);
        changed[40] ^= 0x01;
        hs[0] = changed;
        try c.submitHeaders(hs, sigs, "", new uint256[](0)) {
            revert("altered root accepted");
        } catch (bytes memory failure) {
            require(bytes4(failure) == LiquidLightClient.BadSignature.selector, "wrong altered-root rejection");
        }

        hs[0] = HEADER;
        sigs[0].s ^= bytes32(uint256(1));
        try c.submitHeaders(hs, sigs, "", new uint256[](0)) {
            revert("altered signature accepted");
        } catch (bytes memory failure) {
            require(bytes4(failure) == LiquidLightClient.BadSignature.selector, "wrong altered-signature rejection");
        }

        sigs[0].s = S;
        c.submitHeaders(hs, sigs, "", new uint256[](0));
        require(c.lcTipHeight() == 2664000, "wrong height");
        // Blockstream displays the same 32 bytes in reversed order.
        require(c.lcTipHash() == 0xb77ea74bbc1570220ac2cd646f6f6ee19a48b1fd9ea00011c93830b6115d191a, "wrong block id");

        bytes32[] memory sibling = new bytes32[](1);
        sibling[0] = TX1;
        require(c.txMerkleRoot(TX0, sibling, 0) == MERKLE_ROOT, "wrong transaction branch");
        require(
            c.blockHeight(LiquidLightClient.BlockRef(0, 0, new bytes32[](0)), MERKLE_ROOT) == 2664000,
            "wrong batch opening"
        );
        sibling[0] ^= bytes32(uint256(1));
        require(c.txMerkleRoot(TX0, sibling, 0) != MERKLE_ROOT, "altered branch accepted");
    }
}
