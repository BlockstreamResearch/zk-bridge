// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {BridgeDeposits} from "../contracts/BridgeDeposits.sol";
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

    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function deal(address account, uint256 balance) external;
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
    function etch(address target, bytes calldata code) external;
    function expectRevert(bytes4 revertData) external;
    function createWallet(uint256 privateKey) external returns (Wallet memory);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// A model of a relay-only admission rule: deposits open while the Liquid light client is current, and nothing
/// else. The hazard test below runs it beside BridgeEscrow to show what the window and the fork check add.
contract RelayGatedDeposits is BridgeDeposits, LiquidLightClient {
    uint256 private immutable lag;

    constructor(uint256 maxRelayLag, Checkpoint memory cp) LiquidLightClient(cp) {
        lag = maxRelayLag;
    }

    function depositsOpen() external view returns (bool) {
        return _depositsOpen();
    }

    function _depositsOpen() internal view override returns (bool) {
        return lcTipTime != 0 && block.timestamp <= uint256(lcTipTime) + lag;
    }
}

/// Deposit admission of BridgeEscrow, over a 1-of-1 federation of synthetic DynaFed headers whose times the
/// tests choose, and a synthetic Sepolia beacon chain whose states the tests prove through a stand-in for
/// EIP-4788. Redemption, deposits and the light client are covered by BridgeEscrow.t.sol and
/// LiquidLightClient.t.sol.
///
/// The hazard: the instance's SP1 guest stops verifying Sepolia at a fork outside its pinned schedule, NEXT,
/// which activates at FORK below. From then on no deposit can enter the proven Liquid accumulator, while
/// anyone can still relay fresh Liquid headers.
///
/// Not covered here: nothing runs a deposit through Sepolia finality, SP1 and the Liquid claim. The beacon states here are synthetic; BridgeEscrowForkProof.t.sol
/// checks checkFork's layout against a real Sepolia state root, and a deployment must also pass a real proof.
contract BridgeEscrowAdmissionTest is SepoliaBeacon {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 constant UNIT = 10_000_000_000;
    bytes32 constant ASSET = 0x2df6418545e8293859defb9b9835cee5f139fc94157a5fbd4ffdbb4e2029472e;
    bytes32 constant LBTC = 0x499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c14;
    uint32 constant EPOCH = 1000;
    uint32 constant CHECKPOINT = 1999;
    uint32 constant LAG = 1 days;
    uint32 constant AGE = 1 hours; // MAX_FORK_CHECK_AGE
    uint256 constant SIGNER = 0x5eed;
    // Deployment at an epoch boundary (an epoch is 384 seconds), and the fork the guest does not cover.
    uint64 constant T0 = GENESIS + 354_860 * 384;
    bytes4 constant NEXT = 0x90000077;
    uint64 constant NEXT_EPOCH = 354_860 + 13_500;
    uint64 constant FORK = T0 + 60 days; // the first slot of NEXT_EPOCH
    uint64 constant END = FORK - 2 days; // depositsEnd, exactly FORK_MARGIN before it
    uint64 constant NONE = type(uint64).max; // no fork outside the pin announced at deployment
    address constant CLOSER = address(0xC105E);
    address payable constant ALICE = payable(address(0xA11CE5));
    // A P2WPKH scriptPubKey: what an ordinary Liquid wallet's unconfidential segwit address pays.
    bytes constant WPKH = hex"0014" hex"1111111111111111111111111111111111111111";

    bytes witnessScript;
    uint256[] keyY;
    bytes sbs; // P2WSH(witnessScript), the headers' signblockscript

    function setUp() public {
        vm.deal(address(this), 1_000 ether);
        vm.warp(T0);
        vm.etch(BEACON_ROOTS, address(new BeaconRootsMock()).code);
        Vm.Wallet memory w = vm.createWallet(SIGNER);
        witnessScript = abi.encodePacked(
            hex"51" hex"21",
            (w.publicKeyY & 1) == 1 ? bytes1(0x03) : bytes1(0x02),
            bytes32(w.publicKeyX),
            hex"51" hex"ae"
        );
        keyY.push(w.publicKeyY);
        sbs = abi.encodePacked(hex"0020", sha256(witnessScript));
    }

    // ---- fixtures ----

    function checkpoint() internal view returns (LiquidLightClient.Checkpoint memory) {
        return LiquidLightClient.Checkpoint(EPOCH, CHECKPOINT, keccak256("checkpoint block"), witnessScript, keyY);
    }

    function admission(uint64 end, uint64 unsupportedForkAt, address closer)
        internal
        pure
        returns (BridgeEscrow.Admission memory)
    {
        return BridgeEscrow.Admission(end, unsupportedForkAt, closer, AGE, GVR, GLOAS, GLOAS_EPOCH);
    }

    /// An escrow whose deployer states NEXT's activation at FORK.
    function deploy(uint64 end, address closer) internal returns (BridgeEscrow) {
        return deploy(end, FORK, closer);
    }

    function deploy(uint64 end, uint64 unsupportedForkAt, address closer) internal returns (BridgeEscrow) {
        return new BridgeEscrow(ASSET, 2, LAG, admission(end, unsupportedForkAt, closer), checkpoint());
    }

    function le32(uint32 x) internal pure returns (bytes4) {
        return bytes4(((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | (x >> 24));
    }

    function sha256d(bytes memory b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(b)));
    }

    function header(bytes32 prev, bytes32 root, uint256 height, uint64 time) internal view returns (bytes memory) {
        return abi.encodePacked(
            le32(0xa0000000),
            prev,
            root,
            le32(uint32(time)),
            le32(uint32(height)),
            hex"01",
            uint8(sbs.length),
            sbs,
            le32(1416),
            bytes32(uint256(0xe1)),
            hex"00"
        );
    }

    /// Relays two headers on `c`'s tip, both stamped `time`, the first with Merkle root `firstRoot`, and
    /// returns that first block's reference. The light client takes header times as signed, so the
    /// tests can stamp them freely; the last header's time becomes lcTipTime.
    function relay(LiquidLightClient c, bytes32 firstRoot, uint64 time)
        internal
        returns (LiquidLightClient.BlockRef memory)
    {
        bytes[] memory hs = new bytes[](2);
        uint256 height = uint256(c.lcTipHeight()) + 1;
        bytes32 second = keccak256(abi.encode("filler", height + 1));
        hs[0] = header(c.lcTipHash(), firstRoot, height, time);
        hs[1] = header(sha256d(hs[0]), second, height + 1, time);
        (, bytes32 r, bytes32 s) = vm.sign(SIGNER, sha256d(hs[1]));
        LiquidLightClient.Signature[] memory sigs = new LiquidLightClient.Signature[](1);
        sigs[0] = LiquidLightClient.Signature(r, s);
        uint256 batch = c.submitHeaders(hs, sigs, "", new uint256[](0));
        bytes32[] memory path = new bytes32[](1);
        path[0] = keccak256(abi.encodePacked(second));
        return LiquidLightClient.BlockRef(batch, 0, path);
    }

    function relayEmpty(LiquidLightClient c, uint64 time) internal {
        relay(c, keccak256(abi.encode("no burn", c.lcTipHeight())), time);
    }

    function explicitOutput(bytes32 asset, uint64 value, bytes memory spk) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"01", asset, hex"01", value, hex"00", uint8(spk.length), spk);
    }

    /// One input, the burn as output 0 and an L-BTC fee as output 1.
    function burnTx(bytes32 asset, bytes memory spk, uint64 units) internal pure returns (bytes memory) {
        return bytes.concat(
            hex"0200000000" hex"01",
            bytes32(uint256(0xcc)),
            hex"00000000" hex"00" hex"ffffffff",
            hex"02",
            explicitOutput(asset, units, spk),
            explicitOutput(LBTC, 300, ""),
            hex"00000000"
        );
    }

    /// Whether a 0.001 ETH deposit to `e` succeeds now; a refused one must leave no trace.
    function tryDeposit(BridgeDeposits e) internal returns (bool ok) {
        uint256 balance = address(e).balance;
        bytes32 acc = e.accumulator();
        uint64 count = e.depositCount();
        bytes memory ret;
        (ok, ret) = address(e).call{value: 0.001 ether}(abi.encodeCall(BridgeDeposits.deposit, (WPKH)));
        if (ok) {
            require(address(e).balance == balance + 0.001 ether && e.depositCount() == count + 1, "a deposit was taken");
        } else {
            require(bytes4(ret) == BridgeDeposits.DepositsClosed.selector, "refused as closed");
            require(
                address(e).balance == balance && e.accumulator() == acc && e.depositCount() == count, "nothing taken"
            );
        }
    }

    /// The proof for `timestamp` on this chain: the state of the slot before the timestamp's (EIP-4788 holds
    /// the parent block's root), under Gloas before FORK and under NEXT from FORK's slot on.
    function beacon(uint64 timestamp) internal returns (BridgeEscrow.BeaconProof memory) {
        uint64 slot = (timestamp - GENESIS) / 12 - 1;
        if (slot / 32 < NEXT_EPOCH) return beaconState(timestamp, GVR, slot, FULU, GLOAS, GLOAS_EPOCH);
        return beaconState(timestamp, GVR, slot, GLOAS, NEXT, NEXT_EPOCH);
    }

    /// The time of the slot `beacon(timestamp)` proves.
    function slotTime(uint64 timestamp) internal pure returns (uint64) {
        return GENESIS + ((timestamp - GENESIS) / 12 - 1) * 12;
    }

    /// Warps to `t`, relays Liquid headers stamped `t` and proves the beacon state at `t`, which together keep
    /// an escrow open. Returns whether the proven fork was the pinned one.
    function tick(BridgeEscrow e, uint64 t) internal returns (bool pinned) {
        vm.warp(t);
        relayEmpty(e, t);
        return e.checkFork(beacon(t));
    }

    // ---- the hazard ----

    /// The same history under both admission rules: constructed at T0, relayed and fork-proven daily, with a
    /// deposit each day until a day after FORK. The relay-lag rule alone takes ETH from FORK on into
    /// accumulator states no Liquid update can prove. BridgeEscrow refuses from END on, the full FORK_MARGIN
    /// before FORK.
    function testRelayedHeadersCannotKeepDepositsOpenPastTheEnd() public {
        require(FORK == GENESIS + NEXT_EPOCH * 384, "FORK is NEXT's first slot");
        RelayGatedDeposits relayOnly = new RelayGatedDeposits(LAG, checkpoint());
        BridgeEscrow e = deploy(END, address(0));
        require(e.UNSUPPORTED_FORK_AT() - e.depositsEnd() == e.FORK_MARGIN(), "the fixture keeps the margin");
        uint64 afterFork;
        for (uint64 t = T0; t <= FORK + 1 days; t += 1 days) {
            require(tick(e, t) == (t <= FORK), "the pinned fork until FORK");
            relayEmpty(relayOnly, t);
            require(tryDeposit(relayOnly), "the relay-lag rule accepts whenever the Liquid tip is fresh");
            require(tryDeposit(e) == (t < END), "BridgeEscrow accepts exactly before depositsEnd");
            if (t >= FORK) afterFork++;
        }
        require(
            afterFork == 2 && relayOnly.depositsOpen() && !e.depositsOpen(), "after the fork, only the model is open"
        );
        require(relayOnly.depositCount() == 62 && e.depositCount() == 58, "the model took the 4 deposits from END on");
    }

    /// An unannounced fork inside the window, and no closer. Relayers keep the Liquid tip fresh, which alone
    /// would keep deposits open for good. The first proof of the new fork ends them for good. Until someone
    /// sends one, the last pinned proof still admits deposits after activation. That is the residual, at most
    /// MAX_FORK_CHECK_AGE, and only closing before activation removes it.
    function testProvingAnUnannouncedForkEndsDepositsForGood() public {
        BridgeEscrow e = deploy(T0 + 180 days, NONE, address(0)); // a window that outlasts FORK
        require(tick(e, FORK - 1 minutes) && tryDeposit(e), "open under the pinned fork");
        vm.warp(FORK + 1 minutes);
        relayEmpty(e, FORK + 1 minutes);
        require(tryDeposit(e), "the residual: admitted after activation, before anyone proves the new fork");

        vm.recordLogs();
        require(!e.checkFork(beacon(FORK + 1 minutes)), "the new fork");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 2, "UnsupportedFork and DepositsEndMoved");
        (bytes4 version, uint64 epoch) = abi.decode(logs[0].data, (bytes4, uint64));
        require(version == NEXT && epoch == NEXT_EPOCH, "UnsupportedFork names the fork");
        require(e.depositsEnd() == FORK + 1 minutes && !e.depositsOpen() && !tryDeposit(e), "closed at once");

        require(e.checkFork(beacon(FORK - 1 minutes)), "a pinned state from before activation still verifies");
        vm.warp(FORK + 2 minutes);
        relayEmpty(e, FORK + 2 minutes);
        require(!e.depositsOpen() && !tryDeposit(e), "but neither it nor a fresh Liquid tip reopens deposits");
    }

    /// If nobody proves the new fork, deposits lapse MAX_FORK_CHECK_AGE after the slot of the last state proven
    /// under the pinned fork, however fresh the Liquid tip. After activation no such state exists.
    function testDepositsLapseWithoutAForkProof() public {
        BridgeEscrow e = deploy(T0 + 180 days, NONE, address(0));
        uint64 t = FORK - 10 minutes;
        require(tick(e, t), "pinned");
        uint64 lapse = slotTime(t) + AGE;
        require(e.forkCheckedAt() == slotTime(t) && lapse > FORK, "the last pinned state, an age before the lapse");
        vm.warp(lapse);
        relayEmpty(e, lapse);
        require(tryDeposit(e), "open at the edge of the age");
        vm.warp(lapse + 1);
        relayEmpty(e, lapse + 1);
        require(!e.depositsOpen() && !tryDeposit(e), "lapsed, though relayed");
        require(!e.checkFork(beacon(lapse + 1)) && e.depositsEnd() == lapse + 1, "and the next proof ends them");
    }

    // ---- the fork check ----

    /// Freshness comes from the proven slot, not from when the proof is sent: an old state proven late keeps
    /// its own age, and an older proof never moves forkCheckedAt back.
    function testForkCheckAgesFromTheProvenSlot() public {
        BridgeEscrow e = deploy(END, address(0));
        BridgeEscrow.BeaconProof memory early = beacon(T0 + 1 hours);
        vm.warp(T0 + 3 hours);
        relayEmpty(e, T0 + 3 hours);
        require(e.checkFork(early) && e.forkCheckedAt() == slotTime(T0 + 1 hours), "pinned");
        require(!e.depositsOpen() && !tryDeposit(e), "two hours old: closed");
        require(e.checkFork(beacon(T0 + 3 hours)) && tryDeposit(e), "a fresh state opens");
        require(e.checkFork(early) && e.forkCheckedAt() == slotTime(T0 + 3 hours), "not moved back");
    }

    function testForkProofsMustReachTheBeaconRoot() public {
        BridgeEscrow e = deploy(END, address(0));
        uint64 t = T0 + 1 hours;
        vm.warp(t);
        BridgeEscrow.BeaconProof memory p = beacon(t);
        p.timestamp = t + 12; // EIP-4788 holds no root for it
        vm.expectRevert(BridgeEscrow.NoBeaconRoot.selector);
        e.checkFork(p);
        p = beacon(t);
        p.currentVersion = NEXT; // nobody can claim a fork the chain is not on
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        p = beacon(t);
        p.slot += 100; // or a fresher slot
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        p = beacon(t);
        p.genesisTime += 1200; // or a fresher slot time
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        p = beacon(t);
        p.stateBranch[1] ^= bytes32(uint256(1));
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        p = beacon(t);
        p.stateBranch[0] ^= bytes32(uint256(1));
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        p = beacon(t);
        p.activeFields ^= bytes32(uint256(1));
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        p = beacon(t);
        p.blockBranch[2] ^= bytes32(uint256(1));
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        // A root that verifies, of a state whose genesis_time is inactive: its zero root reads as genesis time 0,
        // so a slot time decades early. Only the active-fields bits tell it apart.
        p = beacon(t);
        p.genesisTime = 0;
        p = prove(p, activeBits(1, 45));
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        // A root that verifies, but for a state whose field 1 is not Sepolia's genesis validators root:
        // another chain, or a layout checkFork does not read.
        p = beaconState(t, keccak256("another chain"), (t - GENESIS) / 12 - 1, FULU, GLOAS, GLOAS_EPOCH);
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        // A state whose slot is not before the timestamp's block.
        p = beaconState(t, GVR, (t - GENESIS) / 12, FULU, GLOAS, GLOAS_EPOCH);
        vm.expectRevert(BridgeEscrow.BadBeaconProof.selector);
        e.checkFork(p);
        // A state under a fork older than the pin's says nothing about the chain now.
        p = beaconState(t, GVR, (t - GENESIS) / 12 - 1, bytes4(0x90000074), FULU, GLOAS_EPOCH - 1000);
        vm.expectRevert(BridgeEscrow.StaleFork.selector);
        e.checkFork(p);
        require(e.forkCheckedAt() == 0 && e.depositsEnd() == END, "nothing changed");
    }

    /// checkFork reads fields 0 to 3 at their progressive indices whatever else the state holds. A fork that
    /// appends or retires later fields changes only the active-fields bits, so its first proof still ends deposits.
    function testForkProofsReadOnlyFieldsZeroToThree() public {
        BridgeEscrow e = deploy(T0 + 180 days, NONE, address(0));
        vm.warp(FORK - 1 hours);
        BridgeEscrow.BeaconProof memory p = beacon(FORK - 1 hours);
        p = prove(p, activeBits(0, 30)); // fields 31 to 45 retired
        require(e.checkFork(p) && e.forkCheckedAt() == slotTime(FORK - 1 hours), "pinned, whatever the later fields");
        vm.warp(FORK + 1 hours);
        p = beacon(FORK + 1 hours);
        p = prove(p, activeBits(0, 3) | activeBits(5, 90)); // NEXT retires field 4 and appends 45 fields
        require(!e.checkFork(p) && e.depositsEnd() == FORK + 1 hours, "the new fork ends deposits");
    }

    /// A pin with the wrong version closes at the first proof, so it never admits deposits into a path the
    /// guest may not verify. A pin for a fork not yet active never opens.
    function testAWrongPinNeverAdmits() public {
        BridgeEscrow wrong = new BridgeEscrow(
            ASSET, 2, LAG, BridgeEscrow.Admission(END, FORK, address(0), AGE, GVR, FULU, GLOAS_EPOCH), checkpoint()
        );
        require(
            !tick(wrong, T0 + 1 hours) && wrong.depositsEnd() == T0 + 1 hours && !tryDeposit(wrong), "closed for good"
        );
        BridgeEscrow early = new BridgeEscrow(
            ASSET, 2, LAG, BridgeEscrow.Admission(END, FORK, address(0), AGE, GVR, NEXT, NEXT_EPOCH), checkpoint()
        );
        relayEmpty(early, T0 + 1 hours);
        BridgeEscrow.BeaconProof memory p = beacon(T0 + 1 hours);
        vm.expectRevert(BridgeEscrow.StaleFork.selector);
        early.checkFork(p);
        require(!tryDeposit(early), "never opens");
    }

    // ---- the window ----

    function testDepositsEndAtTheEndAndNothingReopensThem() public {
        BridgeEscrow e = deploy(END, address(0));
        require(!e.depositsOpen() && !tryDeposit(e), "closed before anything is relayed or proven");
        require(e.checkFork(beacon(T0)) && !tryDeposit(e), "a fork proof alone does not open");
        relayEmpty(e, T0);
        require(tryDeposit(e), "open with both");
        require(tick(e, END - 1) && e.depositsOpen() && tryDeposit(e), "open in the window's last second");
        vm.warp(END);
        require(!e.depositsOpen() && !tryDeposit(e), "closed at depositsEnd");
        // END is two days before FORK, so the chain is still on the pinned fork here.
        require(
            tick(e, END + 12 hours) && !e.depositsOpen() && !tryDeposit(e),
            "fresh headers and pinned proofs do not reopen"
        );
    }

    function testRelayLagStillClosesInsideTheWindow() public {
        BridgeEscrow e = deploy(END, address(0));
        relayEmpty(e, T0);
        vm.warp(T0 + LAG);
        e.checkFork(beacon(T0 + LAG));
        require(tryDeposit(e), "open at the edge of the lag");
        vm.warp(T0 + LAG + 1);
        require(!e.depositsOpen() && !tryDeposit(e), "closed once the light client trails by more than the lag");
        relayEmpty(e, T0 + LAG + 1);
        require(tryDeposit(e), "relaying reopens deposits inside the window");
    }

    // ---- the closer ----

    function testCloserEndsAFixedMarginBeforeAnAnnouncedFork() public {
        BridgeEscrow e = deploy(END, CLOSER);
        // A fork announced after deployment, to activate before END.
        uint64 fork = T0 + 20 days;
        vm.expectRevert(BridgeEscrow.NotDepositCloser.selector);
        e.endDepositsBefore(fork); // anyone else
        vm.prank(CLOSER);
        vm.expectRevert(BridgeEscrow.DepositsEndNotEarlier.selector);
        e.endDepositsBefore(END + 2 days); // an end that is not before the current one
        vm.prank(CLOSER);
        vm.expectRevert(BridgeEscrow.DepositsEndNotEarlier.selector);
        e.endDepositsBefore(type(uint64).max);

        vm.recordLogs();
        vm.prank(CLOSER);
        e.endDepositsBefore(fork);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1 && abi.decode(logs[0].data, (uint64)) == fork - 2 days, "DepositsEndMoved");
        require(e.FORK_MARGIN() == 2 days && e.depositsEnd() == fork - e.FORK_MARGIN(), "the margin is the contract's");

        require(tick(e, fork - 2 days - 1) && tryDeposit(e), "open until the new end");
        require(tick(e, fork - 2 days) && !tryDeposit(e), "closed at the new end, though relayed and proven");
        vm.prank(CLOSER);
        vm.expectRevert(BridgeEscrow.DepositsEndNotEarlier.selector);
        e.endDepositsBefore(fork + 1 days); // the closer cannot reopen them either
    }

    function testALateCloserClosesAtOnce() public {
        BridgeEscrow e = deploy(END, CLOSER);
        require(tick(e, T0 + 1 days) && tryDeposit(e), "open");
        vm.prank(CLOSER);
        e.endDepositsBefore(T0 + 2 days); // an activation a day away, inside the margin
        require(e.depositsEnd() == T0 && !e.depositsOpen() && !tryDeposit(e), "closed in the same block");
        vm.prank(CLOSER);
        e.endDepositsBefore(1 days); // an activation sooner than the margin's length after time zero
        require(e.depositsEnd() == 0, "ends at zero");
        vm.prank(CLOSER);
        vm.expectRevert(BridgeEscrow.DepositsEndNotEarlier.selector);
        e.endDepositsBefore(0);
    }

    function testZeroCloserMeansNobody() public {
        BridgeEscrow e = deploy(END, address(0));
        vm.prank(address(0));
        vm.expectRevert(BridgeEscrow.NotDepositCloser.selector);
        e.endDepositsBefore(T0);
        require(e.depositsEnd() == END, "unchanged");
    }

    // ---- what admission does not touch ----

    /// After deposits end, a burn still redeems, and the accumulator Liquid claims against stays in slot 0
    /// and unchanged.
    function testRedemptionsAreNeverGated() public {
        BridgeEscrow e = deploy(END, address(0));
        tick(e, T0);
        e.deposit{value: 1 ether}(WPKH);
        bytes32 acc = e.accumulator();
        vm.warp(FORK + 1 hours);
        require(!e.checkFork(beacon(FORK + 1 hours)), "the new fork");

        vm.warp(FORK + 30 days); // long after the end, with the light client lagging and no fork proof since
        bytes memory raw = burnTx(ASSET, e.burnScriptPubKey(ALICE), 100_000);
        LiquidLightClient.BlockRef memory ref = relay(e, sha256d(raw), T0 + 1); // a one-transaction block
        require(!e.depositsOpen(), "closed");
        e.redeem(ALICE, BridgeEscrow.BurnProof(raw, 0, new bytes32[](0), 0), ref);
        require(ALICE.balance == 100_000 * UNIT && e.isRedeemed(sha256d(raw), 0), "redeemed after the end");
        require(e.accumulator() == acc && e.depositCount() == 1, "the accumulator is the deposits' alone");
        require(vm.load(address(e), bytes32(0)) == acc, "slot 0 is the accumulator");
        require(
            e.DOMAIN() == sha256(abi.encodePacked("liquid-bridge-poc/deposit", block.chainid, address(e))),
            "the claim leaf's domain"
        );
    }

    // ---- fuzzed rule ----

    /// For any Liquid tip time, fork proof time, closer move and later block time: open exactly before the
    /// (possibly moved) end, within the relay lag and within the fork-check age of a pinned proof, and a
    /// deposit succeeds exactly when open.
    function testFuzzOpenExactlyWhenAllThreeRulesAllow(
        uint64 tipOffset,
        uint64 checkOffset,
        uint64 activation,
        uint64 nowOffset,
        bool move
    ) public {
        BridgeEscrow e = deploy(END, CLOSER);
        uint64 tip = T0 + tipOffset % (100 days);
        relayEmpty(e, tip);
        uint64 c = T0 + checkOffset % (100 days);
        vm.warp(c);
        require(e.checkFork(beacon(c)) == (c < FORK + 12), "pinned before the new fork's first slot");
        uint64 end = modelEnd(c, activation, move);
        if (end < e.depositsEnd()) {
            vm.prank(CLOSER);
            e.endDepositsBefore(activation);
        }
        require(e.depositsEnd() == end, "depositsEnd");
        uint256 t = uint256(c) + nowOffset % (100 days);
        vm.warp(t);
        bool expected = t < end && c < FORK + 12 && t <= uint256(slotTime(c)) + AGE && t <= uint256(tip) + LAG;
        require(e.depositsOpen() == expected, "depositsOpen");
        require(tryDeposit(e) == expected, "deposit");
    }

    /// depositsEnd after a proof at `c` (which ends deposits from the new fork's first slot on) and, if
    /// `move`, the closer's call for `activation`.
    function modelEnd(uint64 c, uint64 activation, bool move) internal pure returns (uint64 end) {
        end = c < FORK + 12 || END <= c ? END : c;
        uint64 moved = activation > 2 days ? activation - 2 days : 0;
        if (move && moved < end) end = moved;
    }

    // ---- deployment ----

    function testConstructorBoundsTheAdmission() public {
        vm.expectRevert(BridgeEscrow.BadDepositsEnd.selector);
        deploy(T0, CLOSER); // ends before it opens
        vm.expectRevert(BridgeEscrow.BadDepositsEnd.selector);
        deploy(T0 - 1, CLOSER);
        vm.expectRevert(BridgeEscrow.BadDepositsEnd.selector);
        deploy(T0 + 180 days + 1, CLOSER); // longer than MAX_DEPOSIT_WINDOW
        vm.expectRevert(BridgeEscrow.BadDepositsEnd.selector);
        deploy(type(uint64).max, CLOSER); // open-ended
        BridgeEscrow e = deploy(T0 + 180 days, NONE, CLOSER);
        require(
            e.depositsEnd() == T0 + 180 days && e.DEPOSIT_CLOSER() == CLOSER && e.forkCheckedAt() == 0,
            "bounds are inclusive"
        );
        require(e.MAX_FORK_CHECK_AGE() == AGE && e.GENESIS_VALIDATORS_ROOT() == GVR, "the age and the chain");
        require(e.FORK_VERSION() == GLOAS && e.FORK_EPOCH() == GLOAS_EPOCH, "the pin");

        BridgeEscrow.Admission memory a = admission(END, FORK, CLOSER);
        a.maxForkCheckAge = 10 minutes - 1;
        vm.expectRevert(BridgeEscrow.BadForkCheckAge.selector);
        new BridgeEscrow(ASSET, 2, LAG, a, checkpoint());
        a.maxForkCheckAge = 6 hours + 1;
        vm.expectRevert(BridgeEscrow.BadForkCheckAge.selector);
        new BridgeEscrow(ASSET, 2, LAG, a, checkpoint());
        a.maxForkCheckAge = 10 minutes;
        new BridgeEscrow(ASSET, 2, LAG, a, checkpoint());
        a.maxForkCheckAge = 6 hours;
        new BridgeEscrow(ASSET, 2, LAG, a, checkpoint());
        a.genesisValidatorsRoot = bytes32(0);
        vm.expectRevert(BridgeEscrow.ZeroGenesisValidatorsRoot.selector);
        new BridgeEscrow(ASSET, 2, LAG, a, checkpoint());
    }

    /// A fork outside the pin already announced at deployment: depositsEnd must leave FORK_MARGIN before it.
    function testConstructorKeepsTheMarginBeforeAnAnnouncedFork() public {
        vm.expectRevert(BridgeEscrow.EndInsideForkMargin.selector);
        deploy(FORK - 1 days, FORK, CLOSER); // a day before the fork
        vm.expectRevert(BridgeEscrow.EndInsideForkMargin.selector);
        deploy(END + 1, FORK, CLOSER); // a second inside the margin
        vm.expectRevert(BridgeEscrow.EndInsideForkMargin.selector);
        deploy(T0 + 180 days, FORK, CLOSER); // a window past the fork
        vm.expectRevert(BridgeEscrow.EndInsideForkMargin.selector);
        deploy(END, 0, CLOSER); // the field forgotten
        vm.expectRevert(BridgeEscrow.EndInsideForkMargin.selector);
        deploy(T0 + 1, T0 + 2 days, CLOSER); // a fork too soon for any window
        vm.expectRevert(BridgeEscrow.BadDepositsEnd.selector);
        deploy(T0, 0, CLOSER); // the window is checked first

        BridgeEscrow e = deploy(T0 + 1, T0 + 1 + 2 days, CLOSER);
        require(e.depositsEnd() == T0 + 1, "the shortest window before the soonest fork");
        e = deploy(END, FORK, CLOSER);
        require(e.depositsEnd() == END && e.UNSUPPORTED_FORK_AT() == FORK, "the bound is inclusive");
        require(tick(e, END - 1) && tryDeposit(e), "the last admitted second");
        require(FORK - (END - 1) > e.FORK_MARGIN(), "is more than the margin before the fork");
        require(tick(e, END) && !tryDeposit(e), "closed from the margin on, though relayed and pinned");
        e = deploy(T0 + 180 days, NONE, CLOSER);
        require(e.UNSUPPORTED_FORK_AT() == NONE, "with none announced, only the window bounds the end");
    }

    /// For any window and announced activation, the constructor accepts exactly when depositsEnd is at least
    /// FORK_MARGIN before the activation, and refuses otherwise for that reason alone.
    function testFuzzConstructorKeepsTheMargin(uint64 endOffset, uint64 forkOffset) public {
        uint64 end = T0 + 1 + endOffset % (180 days);
        uint64 forkAt = T0 + forkOffset % (200 days);
        bool ok = uint256(end) + 2 days <= forkAt;
        BridgeEscrow.Admission memory a = admission(end, forkAt, CLOSER);
        try new BridgeEscrow(ASSET, 2, LAG, a, checkpoint()) returns (BridgeEscrow e) {
            require(ok, "accepted only outside the margin");
            require(e.depositsEnd() - 1 + e.FORK_MARGIN() < e.UNSUPPORTED_FORK_AT(), "no admitted second inside it");
        } catch (bytes memory ret) {
            require(!ok && bytes4(ret) == BridgeEscrow.EndInsideForkMargin.selector, "refused for the margin");
        }
    }
}
