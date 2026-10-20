// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {BridgeEscrow} from "../contracts/BridgeEscrow.sol";
import {LiquidLightClient} from "../contracts/LiquidLightClient.sol";

interface Vm {
    function envString(string calldata name) external view returns (string memory);
    function readFile(string calldata path) external view returns (string memory);
    function writeFile(string calldata path, string calldata data) external;
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function parseJsonUintArray(string calldata json, string calldata key) external pure returns (uint256[] memory);
    function parseJsonAddress(string calldata json, string calldata key) external pure returns (address);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function toString(address value) external pure returns (string memory);
    function toString(bytes32 value) external pure returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
    function startBroadcast() external;
    function stopBroadcast() external;
}

/// Deploys BridgeEscrow from the parameter file `just deploy-params` writes, then reads every immutable and the
/// light client's starting point back from the new contract and refuses any difference.
///
///   FOUNDRY_PROFILE=deploy DEPLOY_PARAMS=../../target/deploy/escrow-params.json \
///     forge script script/DeployBridgeEscrow.s.sol --rpc-url sepolia --sender <deployer>
///
/// `sepolia` is foundry.toml's endpoint, read from SEPOLIA_EXECUTION_RPC; without an RPC, forge would run on a
/// local chain, which `run` refuses. Without --broadcast, forge only simulates. With the real deployer as --sender the
/// simulated escrow has the address and runtime code the broadcast will give, since DOMAIN, an immutable, names
/// the address: `just deploy-record` compares the deployed code hash with this local compilation. Both runs write
/// what they built to DEPLOY_PARAMS with ".expected.json" appended.
contract DeployBridgeEscrow {
    bool public constant IS_SCRIPT = true;

    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 constant SEPOLIA_CHAIN_ID = 11_155_111;

    // The fork pin is the last fork of the guest's committed schedule (tools/sg16/bridge-guest/testnet/pins.py
    // SEPOLIA_FORKS, gloas), on Sepolia's beacon chain: a deployment cannot choose another.
    bytes32 constant GENESIS_VALIDATORS_ROOT = 0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078;
    bytes4 constant FORK_VERSION = 0x90000076;
    uint64 constant FORK_EPOCH = 353_024;

    struct Params {
        bytes32 asset;
        uint32 minConfirmations;
        uint32 maxRelayLag;
        BridgeEscrow.Admission admission;
        LiquidLightClient.Checkpoint checkpoint;
        bytes32 signblockscriptHash;
    }

    function run() external returns (BridgeEscrow escrow) {
        require(block.chainid == SEPOLIA_CHAIN_ID, "the RPC is not Sepolia");
        string memory path = vm.envString("DEPLOY_PARAMS");
        Params memory p = read(vm.readFile(path));

        vm.startBroadcast();
        escrow = new BridgeEscrow(p.asset, p.minConfirmations, p.maxRelayLag, p.admission, p.checkpoint);
        vm.stopBroadcast();

        readBack(escrow, p);
        vm.writeFile(string.concat(path, ".expected.json"), expected(escrow));
    }

    function read(string memory json) internal pure returns (Params memory p) {
        p.asset = vm.parseJsonBytes32(json, ".bridgeAsset");
        p.minConfirmations = u32(vm.parseJsonUint(json, ".minConfirmations"));
        p.maxRelayLag = u32(vm.parseJsonUint(json, ".maxRelayLag"));
        p.admission = BridgeEscrow.Admission({
            depositsEnd: u64(vm.parseJsonUint(json, ".admission.depositsEnd")),
            unsupportedForkAt: u64(vm.parseJsonUint(json, ".admission.unsupportedForkAt")),
            closer: vm.parseJsonAddress(json, ".admission.closer"),
            maxForkCheckAge: u32(vm.parseJsonUint(json, ".admission.maxForkCheckAge")),
            genesisValidatorsRoot: GENESIS_VALIDATORS_ROOT,
            forkVersion: FORK_VERSION,
            forkEpoch: FORK_EPOCH
        });

        // The checkpoint as tools/liquid-relay/relay.py checkpoint printed it, checked against Liquid there.
        p.checkpoint = LiquidLightClient.Checkpoint({
            epochLength: u32(vm.parseJsonUint(json, ".checkpoint.epochLength")),
            height: u32(vm.parseJsonUint(json, ".checkpoint.height")),
            hash: vm.parseJsonBytes32(json, ".checkpoint.hash"),
            witnessScript: vm.parseJsonBytes(json, ".checkpoint.witnessScript"),
            keyY: vm.parseJsonUintArray(json, ".checkpoint.keyY")
        });
        p.signblockscriptHash = vm.parseJsonBytes32(json, ".checkpoint.signblockscriptKeccak");
    }

    /// Every value the constructor fixed, read from the contract: a parameter the encoding lost or a wrong file
    /// stops here, before the record is written.
    function readBack(BridgeEscrow e, Params memory p) internal view {
        BridgeEscrow.Admission memory a = p.admission;

        require(e.BRIDGE_ASSET() == p.asset, "BRIDGE_ASSET");
        require(e.MIN_CONFIRMATIONS() == p.minConfirmations, "MIN_CONFIRMATIONS");
        require(e.MAX_RELAY_LAG() == p.maxRelayLag, "MAX_RELAY_LAG");
        require(e.BURN_CHAIN_ID() == SEPOLIA_CHAIN_ID, "BURN_CHAIN_ID");
        require(e.depositsEnd() == a.depositsEnd, "depositsEnd");
        require(e.UNSUPPORTED_FORK_AT() == a.unsupportedForkAt, "UNSUPPORTED_FORK_AT");
        require(e.DEPOSIT_CLOSER() == a.closer, "DEPOSIT_CLOSER");
        require(e.MAX_FORK_CHECK_AGE() == a.maxForkCheckAge, "MAX_FORK_CHECK_AGE");
        require(e.GENESIS_VALIDATORS_ROOT() == GENESIS_VALIDATORS_ROOT, "GENESIS_VALIDATORS_ROOT");
        require(e.FORK_VERSION() == FORK_VERSION && e.FORK_EPOCH() == FORK_EPOCH, "fork pin");
        require(e.EPOCH_LENGTH() == p.checkpoint.epochLength, "EPOCH_LENGTH");
        require(e.lcTipHeight() == p.checkpoint.height, "lcTipHeight");
        require(e.lcTipHash() == p.checkpoint.hash, "lcTipHash");
        require(e.signblockscriptHash() == p.signblockscriptHash, "signblockscriptHash");
        require(
            e.DOMAIN() == sha256(abi.encodePacked("liquid-bridge-poc/deposit", block.chainid, address(e))), "DOMAIN"
        );
    }

    function expected(BridgeEscrow e) internal view returns (string memory) {
        return string.concat(
            '{\n "escrow": "',
            vm.toString(address(e)),
            '",\n "codeHash": "',
            vm.toString(address(e).codehash),
            '",\n "domain": "',
            vm.toString(e.DOMAIN()),
            '",\n "runtimeBytes": ',
            vm.toString(address(e).code.length),
            ',\n "simulatedOnBlock": ',
            vm.toString(block.number),
            "\n}\n"
        );
    }

    function u32(uint256 x) internal pure returns (uint32) {
        require(x <= type(uint32).max, "a parameter exceeds uint32");
        return uint32(x);
    }

    function u64(uint256 x) internal pure returns (uint64) {
        require(x <= type(uint64).max, "a parameter exceeds uint64");
        return uint64(x);
    }
}
