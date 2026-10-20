// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {BridgeEscrow} from "../contracts/BridgeEscrow.sol";
import {LiquidLightClient} from "../contracts/LiquidLightClient.sol";

interface Vm {
    struct Wallet {
        address addr;
        uint256 publicKeyX;
        uint256 publicKeyY;
        uint256 privateKey;
    }

    function chainId(uint256 newChainId) external;
    function etch(address target, bytes calldata code) external;
    function createWallet(uint256 privateKey) external returns (Wallet memory);
    function readFile(string calldata path) external view returns (string memory);
    function keyExistsJson(string calldata json, string calldata key) external view returns (bool);
    function parseJsonString(string calldata json, string calldata key) external pure returns (string memory);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function parseJsonAddress(string calldata json, string calldata key) external pure returns (address);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function toString(uint256 value) external pure returns (string memory);
}

/// The escrow's tag-derived values against the shared protocol vectors (vectors/protocol.json): BURN_TAG,
/// burnScriptPubKey and DOMAIN. Both name the chain id and the escrow's own address, so each case's escrow is
/// constructed at the case's address under the case's chain id.
contract ProtocolVectorsTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string constant VECTORS = "../../vectors/protocol.json";
    bytes32 constant ASSET = keccak256("a synthetic bridge asset");

    /// The JSON key of case `i` of `section`.
    function at(string memory section, uint256 i) internal view returns (string memory) {
        return string.concat(".", section, "[", vm.toString(i), "]");
    }

    /// A recorded 32-byte output; one not yet recorded (null) fails, naming the recorder.
    function recorded(string memory json, string memory key) internal view returns (bytes32 value) {
        try vm.parseJsonBytes32(json, key) returns (bytes32 v) {
            value = v;
        } catch {}
        require(
            value != bytes32(0),
            string.concat(key, " is not recorded: run node vectors/record.mjs and review the result")
        );
    }

    /// An escrow constructed at `where` while the chain id is `chain`, as forge-std's deployCodeTo does it: the
    /// creation code runs at `where`, so the constructor sees that address, and its runtime code replaces it.
    function deployAt(address where, uint256 chain) internal returns (BridgeEscrow) {
        vm.chainId(chain);
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
            uint64(block.timestamp + 30 days),
            type(uint64).max,
            address(0),
            1 hours,
            keccak256("genesis validators root"),
            0x90000076,
            353_024
        );
        bytes memory args = abi.encode(ASSET, uint32(2), uint32(1 days), admission, cp);
        vm.etch(where, bytes.concat(type(BridgeEscrow).creationCode, args));
        (bool ok, bytes memory runtime) = where.call("");
        require(ok, "escrow constructor");
        vm.etch(where, runtime);
        return BridgeEscrow(where);
    }

    function testBurnTagAndScripts() public {
        string memory json = vm.readFile(VECTORS);
        bytes memory tag = bytes(vm.parseJsonString(json, ".tags.burn"));
        uint256 i;
        for (; vm.keyExistsJson(json, at("burn_script", i)); i++) {
            string memory c = at("burn_script", i);
            uint256 chain = vm.parseJsonUint(json, string.concat(c, ".chain_id"));
            address recipient = vm.parseJsonAddress(json, string.concat(c, ".recipient"));
            bytes memory script = vm.parseJsonBytes(json, string.concat(c, ".script"));
            BridgeEscrow e = deployAt(vm.parseJsonAddress(json, string.concat(c, ".escrow")), chain);
            require(tag.length == 22 && e.BURN_TAG() == bytes22(tag), "BURN_TAG = tags.burn");
            require(e.BURN_CHAIN_ID() == chain, string.concat(c, ": BURN_CHAIN_ID"));
            require(
                script.length == 72 && keccak256(e.burnScriptPubKey(recipient)) == keccak256(script),
                string.concat(c, ": burnScriptPubKey")
            );
        }
        require(i > 0, "vectors: no burn_script case");
    }

    function testDepositDomain() public {
        string memory json = vm.readFile(VECTORS);
        uint256 i;
        for (; vm.keyExistsJson(json, at("deposit_domain", i)); i++) {
            string memory c = at("deposit_domain", i);
            bytes32 domain = recorded(json, string.concat(c, ".domain"));
            uint256 chain = vm.parseJsonUint(json, string.concat(c, ".chain_id"));
            BridgeEscrow e = deployAt(vm.parseJsonAddress(json, string.concat(c, ".escrow")), chain);
            require(e.DOMAIN() == domain, string.concat(c, ": DOMAIN"));
        }
        require(i > 0, "vectors: no deposit_domain case");
    }
}
