// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {BridgeDeposits} from "./BridgeDeposits.sol";
import {ElementsParser} from "./ElementsParser.sol";
import {LiquidLightClient} from "./LiquidLightClient.sol";

/// Native-ETH escrow for one Liquid asset. No owner, upgrade, pause or fallback path; the only role is the
/// optional DEPOSIT_CLOSER below, which can bring the end of deposits forward and nothing else.
///
/// Deposits are BridgeDeposits', the first base, so storage slot 0 is the accumulator the SP1 update
/// proof reads and the Liquid claim covenant (contracts/simplicity/simf/claim.simf) mints deposit i exactly
/// once, in any order, to the Liquid script it commits.
///
/// Redemptions release ETH for bridge-asset units burned on Liquid. Liquid's own consensus is checked
/// directly: LiquidLightClient follows Liquid's signed header chain, epoch by epoch, under the keys
/// current at each height, including DynaFed key changes.
///
///   burn output     explicit BRIDGE_ASSET, explicit value v > 0, scriptPubKey = burnScriptPubKey(r)
///   burnScriptPubKey(r)  OP_RETURN PUSH70 (BURN_TAG || be64 chain id || this || r)    72 bytes, exactly
///   payout          v * UNIT_WEI wei to r, or where r directs (redeemTo), once per burn output (txid, vout)
///
/// The burn is a bare OP_RETURN output. Executing a scriptPubKey that starts with OP_RETURN fails whatever
/// input spends it, so by consensus no spend of the output is valid and the units are gone, with no hash
/// assumption. (Nodes also leave such outputs out of their UTXO set, but that is storage, not the rule.)
/// Anyone reading the chain sees the burn, its amount and, in plain bytes, the chain, escrow and recipient
/// it redeems to. The script has no address, so a burn is built as a transaction (the interface builds one
/// for Humid's signPset), not sent with a wallet's ordinary Send. A wallet's Burn control, like Elements'
/// destroyamount, pays a bare OP_RETURN with no payload, which names no recipient and redeems nothing.
/// A redemption proves that the burn transaction's txid is in the Merkle tree of a relayed block, and
/// that this block has at least MIN_CONFIRMATIONS relayed blocks counting itself.
///
/// Deposit admission. A deposit reaches Liquid only through a Sepolia finality update proven by the
/// instance's SP1 guest, under the fork schedule its Liquid update leaf pins. Once Sepolia activates a fork
/// outside that schedule, no update signed after activation verifies: the Liquid accumulator stops at the
/// last update signed before it, and a later deposit can never be claimed. Nor can it be refunded here,
/// since this contract cannot learn that Liquid will never mint it. Liquid header freshness alone says
/// nothing about that path, and anyone can relay headers. So all three rules below must hold:
///
///   open               block.timestamp < depositsEnd                                          window
///                      && forkCheckedAt != 0 && block.timestamp <= forkCheckedAt + MAX_FORK_CHECK_AGE
///                      && lcTipTime != 0 && block.timestamp <= lcTipTime + MAX_RELAY_LAG      redemption path
///   depositsEnd        set at deployment, at most MAX_DEPOSIT_WINDOW ahead and at least FORK_MARGIN before
///                      UNSUPPORTED_FORK_AT: the deployer's statement of the announced activation time of the
///                      earliest fork outside the pin, or type(uint64).max for none (zero, a forgotten field,
///                      fails). It never increases.
///   endDepositsBefore  DEPOSIT_CLOSER (zero: none) gives the announced activation time of a fork outside the
///                      pin, and depositsEnd becomes that time less FORK_MARGIN. The closer states a public
///                      fact; the margin is fixed here. It cannot reopen or extend deposits, or touch claims,
///                      redemptions or funds.
///   checkFork          anyone proves the beacon state's slot and `fork` through the EIP-4788 beacon block
///                      root. Under the pinned fork (FORK_VERSION, active from FORK_EPOCH) it moves
///                      forkCheckedAt up to that slot's time. Under any later or different fork it ends
///                      deposits for good. If nobody proves anything, deposits lapse; they never stay open.
///
/// The relay-lag rule keeps ETH out of a bridge whose way back nobody maintains: a halted light client
/// (an undecidable DynaFed vote, an unsupported signing script) or one nobody relays falls behind and
/// closes deposits, and relaying opens them again inside the window.
///
/// What admission guarantees, exactly:
///  - No deposit is admitted more than MAX_FORK_CHECK_AGE after the slot of the latest beacon state proven to
///    be under the pinned fork. So after any fork, announced or not and inside the window or not, admission
///    stops within MAX_FORK_CHECK_AGE of activation with nobody acting, and at once when anyone proves the
///    new fork.
///  - That bound comes after the fact. A deposit in the stretch from roughly the last finality update signed
///    before activation until admission stops may never reach Liquid. Only closing before activation avoids
///    that, by depositsEnd or endDepositsBefore, and both need the fork to be known in time. For a fork
///    announced by deployment the constructor holds depositsEnd at least FORK_MARGIN before UNSUPPORTED_FORK_AT,
///    so the last admitted deposit is more than FORK_MARGIN before it. It checks the statement's consistency,
///    not its truth: that it names the earliest such fork in Sepolia's published schedule is for the deployment
///    review, and a fork announced later is for the closer. A fork never announced in time keeps the residual
///    above, up to MAX_FORK_CHECK_AGE after activation.
///  - Nothing here shows that a deposit reached Liquid. That needs a finality update covering it, signed by
///    the sync committee before activation, then kept, proven and submitted to Liquid, and none of these
///    steps is visible on Ethereum. The off-chain completion check is a Liquid state whose proven slot 0
///    equals `accumulator()` (final once deposits close), from an update signed before activation. FORK_MARGIN
///    leaves time to pass it before activation, so no pre-fork update need be kept and proven later. A refund
///    of unclaimed deposits would need Liquid to stop minting them provably: a covenant change, which no
///    escrow rule can replace.
///
/// The pin. FORK_VERSION and FORK_EPOCH must be the last fork in the guest's committed schedule, with its
/// activation epoch, and that fork must be active at deployment. A fork the guest schedules for later still
/// closes deposits when it activates. GENESIS_VALIDATORS_ROOT is Sepolia's. checkFork reads this layout:
///   block root    EIP-4788 root for `timestamp`, the parent beacon block's: a BeaconBlock of five fields,
///                 whose state_root (generalized index 11) lies under nodes 10 (parent_root), 4 and 3
///   state root    a BeaconState that is a ProgressiveContainer (EIP-7495), as from Gloas on: node 2 is the
///                 progressive tree of its field roots (EIP-7916), node 3 its active-fields bits. That tree
///                 holds field 0 alone at node 4, then fields 1 to 4 at nodes 40 to 43 under node 10, and
///                 fields 5 on under node 11. Fields 0 to 4 are genesis_time, genesis_validators_root, slot,
///                 fork and latest_block_header; the proof gives nodes 43, 11 and 3, and the bits of fields 0
///                 to 3 must be set
///   fork          Fork(previous_version, current_version, epoch)
///   slot time     genesis_time + slot * SECONDS_PER_SLOT, which must be before `timestamp`
/// The 64-leaf Container of Electra and Fulu states is not read: EIP-4788 keeps roots for about a day, and a
/// state before the pinned fork proves nothing anyway. Appending fields leaves these indices and changes only
/// node 3, so a later fork that keeps fields 0 to 3 can be proven and ends deposits at once. A layout this
/// does not match yields no proof, so deposits lapse. The deployment check is that a real Sepolia proof
/// passes. A false close would need a SHA-256 collision, since every field is typed and sits at a fixed index.
///
/// Redemptions, and claims of deposits already admitted, are never gated, by any admission rule.
///
/// Payout. A redemption pays with a plain call that gets all remaining gas but 1/64 (EIP-150); if the
/// call fails, the whole redemption reverts and the burn stays unspent. No fixed gas amount appears, so
/// no gas schedule (EIP-8037's state gas, EIP-8038's access prices) changes the outcome: the payee is
/// paid in full, or nothing is recorded. A submitter that sends too little gas only fails its own
/// transaction. A recipient that refuses plain ETH, but can make calls, redeems with `redeemTo` and
/// names where the ETH goes; only it can, because the burn script names it. A recipient that can
/// neither receive ETH nor call this contract cannot redeem; the interface accepts only addresses it
/// can check. A redemption that needs more ETH than the escrow holds, which only a failure of the
/// block signers (L1) can cause, reverts and leaves the burn unspent.
///
/// Conservation, in bridge units (D deposited, M minted on Liquid, B burned to burn outputs, R redeemed):
///   M <= D   the claim covenant mints deposit i once and only after Ethereum proves it
///   B <= M   Elements balance rules, as validated by the block signers (LiquidLightClient L1)
///   R <= B   one payout per burn output, exactly its burned value
/// so balance = (D - R) * UNIT_WEI >= (M - B) * UNIT_WEI.
///
/// The redemption path's assumptions are LiquidLightClient's L1-L3, plus availability of the burn
/// transaction and its block's txids to some submitter. The contract cannot check Liquid transaction
/// validity; it inherits the block signers'. On Liquid testnet the signers are one Blockstream key.
/// That the bridge asset's only reissuance token sits in the claim/update covenant is checked off chain
/// from the public bootstrap transaction (tools/sg16/bridge-guest/testnet assemble.py verify-bootstrap,
/// and the interface), not by this contract.
contract BridgeEscrow is BridgeDeposits, LiquidLightClient {
    error ZeroAsset();
    error ZeroConfirmations();
    error BadRelayLag();
    error BadDepositsEnd();
    error EndInsideForkMargin();
    error BadForkCheckAge();
    error ZeroGenesisValidatorsRoot();
    error ChainIdTooWide();
    error NotDepositCloser();
    error DepositsEndNotEarlier();
    error NoBeaconRoot();
    error BadBeaconProof();
    error StaleFork();
    error ZeroRecipient();
    error ShortTransaction();
    error AlreadyRedeemed();
    error WrongAsset();
    error ZeroAmount();
    error WrongBurnScript();
    error TooFewConfirmations();
    error Insolvent();
    error PayoutFailed();

    /// A burn transaction in txid form, the burn output index, and its Merkle branch in its block.
    struct BurnProof {
        bytes transaction;
        uint32 vout;
        bytes32[] branch;
        uint32 position;
    }

    /// How deposits end (see the contract notes).
    struct Admission {
        uint64 depositsEnd;
        uint64 unsupportedForkAt;
        address closer;
        uint32 maxForkCheckAge;
        bytes32 genesisValidatorsRoot;
        bytes4 forkVersion;
        uint64 forkEpoch;
    }

    /// Beacon state fields 0 to 3, and their branches to the EIP-4788 root for `timestamp`.
    struct BeaconProof {
        uint64 timestamp;
        uint64 genesisTime;
        bytes32 genesisValidatorsRoot;
        uint64 slot;
        bytes4 previousVersion;
        bytes4 currentVersion;
        uint64 epoch;
        bytes32[2] stateBranch; // BeaconState nodes 43 (latest_block_header) and 11 (fields 5 on)
        bytes32 activeFields; // BeaconState node 3: the active-fields bits, field i at bit i % 8 of byte i / 8
        bytes32[3] blockBranch; // BeaconBlock nodes 10, 4, 3
    }

    uint256 public constant MIN_RELAY_LAG = 1 hours;
    uint256 public constant MAX_RELAY_LAG_BOUND = 30 days;
    /// The longest deposit window a deployment may set, so that no instance is open-ended.
    uint256 public constant MAX_DEPOSIT_WINDOW = 180 days;
    uint256 public constant MIN_FORK_CHECK_AGE = 10 minutes;
    uint256 public constant MAX_FORK_CHECK_AGE_BOUND = 6 hours;
    /// How long before an announced fork's activation deposits end: time for the last deposit to finalize
    /// and for a finality update covering it, signed before activation, to be captured. A loss of finality
    /// longer than this is not covered.
    uint64 public constant FORK_MARGIN = 2 days;
    /// Sepolia's slot length. A fork that changed it would also change the fork version, so leave the pin.
    uint256 public constant SECONDS_PER_SLOT = 12;
    /// EIP-4788: the parent beacon block root of the execution block with a given timestamp, for 8191 slots.
    address public constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    /// The first bytes of every burn payload, in ASCII, so that a burn reads as one on any explorer.
    bytes22 public constant BURN_TAG = "liquid-bridge-poc/burn";

    /// Liquid asset id of the bridge asset, internal byte order (the reverse of the displayed id).
    bytes32 public immutable BRIDGE_ASSET;
    /// Relayed blocks a burn needs, counting its own.
    uint256 public immutable MIN_CONFIRMATIONS;
    /// Seconds the light client's tip may trail this block before deposits close.
    uint256 public immutable MAX_RELAY_LAG;
    /// The chain id at deployment, which every burn payload names.
    uint64 public immutable BURN_CHAIN_ID;
    /// The announced activation time of the earliest fork outside the pin, as the deployer stated it;
    /// type(uint64).max for none announced.
    uint64 public immutable UNSUPPORTED_FORK_AT;
    /// The one address that may bring depositsEnd forward; zero for none.
    address public immutable DEPOSIT_CLOSER;
    /// Seconds after the slot of the latest beacon state proven under the pinned fork that deposits stay open.
    uint256 public immutable MAX_FORK_CHECK_AGE;
    bytes32 public immutable GENESIS_VALIDATORS_ROOT;
    bytes4 public immutable FORK_VERSION;
    uint64 public immutable FORK_EPOCH;

    /// The first block time at which deposits are closed for good.
    uint64 public depositsEnd;
    /// Slot time of the latest beacon state proven under the pinned fork; zero before the first proof.
    uint64 public forkCheckedAt;
    mapping(bytes32 => bool) private redeemed; // keccak256(txid || be32 vout)

    /// `recipient` is the burn's; `to` received the ETH (the recipient, unless it used redeemTo).
    event Redeemed(bytes32 indexed txid, uint32 vout, address indexed recipient, address to, uint64 units);
    event DepositsEndMoved(uint64 depositsEnd);
    event ForkChecked(uint64 slotTime);
    event UnsupportedFork(bytes4 version, uint64 epoch);

    /// @param bridgeAsset      the Liquid bridge asset id, internal byte order
    /// @param minConfirmations relayed blocks a burn needs, counting its own (Liquid guidance: 2)
    /// @param maxRelayLag      seconds the light client may trail before deposits close (1 hour .. 30 days)
    /// @param admission        depositsEnd (after this block, at most MAX_DEPOSIT_WINDOW after it, and at least
    ///                         FORK_MARGIN before unsupportedForkAt), unsupportedForkAt, the closer or zero,
    ///                         MAX_FORK_CHECK_AGE (10 minutes .. 6 hours) and the fork pin
    /// @param checkpoint       the last block of a Liquid epoch before the bridge asset's issuance, and the
    ///                         next epoch's block-signing witness script (LiquidLightClient L2)
    constructor(
        bytes32 bridgeAsset,
        uint32 minConfirmations,
        uint32 maxRelayLag,
        Admission memory admission,
        Checkpoint memory checkpoint
    ) LiquidLightClient(checkpoint) {
        if (bridgeAsset == bytes32(0)) revert ZeroAsset();
        if (minConfirmations == 0) revert ZeroConfirmations();
        if (maxRelayLag < MIN_RELAY_LAG || maxRelayLag > MAX_RELAY_LAG_BOUND) revert BadRelayLag();
        if (admission.depositsEnd <= block.timestamp || admission.depositsEnd > block.timestamp + MAX_DEPOSIT_WINDOW) {
            revert BadDepositsEnd();
        }
        // In 256 bits, so no end overflows; a zero or past activation always fails, as depositsEnd > now.
        if (uint256(admission.depositsEnd) + FORK_MARGIN > admission.unsupportedForkAt) revert EndInsideForkMargin();
        if (admission.maxForkCheckAge < MIN_FORK_CHECK_AGE || admission.maxForkCheckAge > MAX_FORK_CHECK_AGE_BOUND) {
            revert BadForkCheckAge();
        }
        if (admission.genesisValidatorsRoot == bytes32(0)) revert ZeroGenesisValidatorsRoot();
        BRIDGE_ASSET = bridgeAsset;
        MIN_CONFIRMATIONS = minConfirmations;
        MAX_RELAY_LAG = maxRelayLag;
        // Every burn names the chain in 8 bytes. Sepolia's 11155111 and any id EIP-2294 allows fit; a wider id
        // would be named wrongly, so it is refused rather than truncated.
        if (block.chainid > type(uint64).max) revert ChainIdTooWide();
        BURN_CHAIN_ID = uint64(block.chainid);
        UNSUPPORTED_FORK_AT = admission.unsupportedForkAt;
        DEPOSIT_CLOSER = admission.closer;
        MAX_FORK_CHECK_AGE = admission.maxForkCheckAge;
        GENESIS_VALIDATORS_ROOT = admission.genesisValidatorsRoot;
        FORK_VERSION = admission.forkVersion;
        FORK_EPOCH = admission.forkEpoch;
        depositsEnd = admission.depositsEnd;
    }

    /// Whether deposits are accepted now (see the contract notes).
    function depositsOpen() external view returns (bool) {
        return _depositsOpen();
    }

    /// Ends deposits FORK_MARGIN before `activation`, the announced activation time of a fork outside the pin.
    /// An activation less than FORK_MARGIN from now, now included, closes them at once. Only DEPOSIT_CLOSER
    /// may call it.
    function endDepositsBefore(uint64 activation) external {
        if (DEPOSIT_CLOSER == address(0) || msg.sender != DEPOSIT_CLOSER) revert NotDepositCloser();
        uint64 end = activation > FORK_MARGIN ? activation - FORK_MARGIN : 0;
        if (end >= depositsEnd) revert DepositsEndNotEarlier();
        _moveEnd(end);
    }

    /// Proves the beacon chain's fork (see the contract notes). Returns whether it is the pinned fork: then
    /// forkCheckedAt moves up to the proven slot's time, if later. Otherwise deposits end for good.
    function checkFork(BeaconProof calldata p) external returns (bool pinned) {
        bytes32 fork =
            _node(_node(bytes32(p.previousVersion), bytes32(p.currentVersion)), _node(_le64(p.epoch), bytes32(0)));
        // Node 10 holds fields 1 to 4; the proof gives field 4, latest_block_header, as node 43.
        bytes32 node10 = _node(_node(p.genesisValidatorsRoot, _le64(p.slot)), _node(fork, p.stateBranch[0]));
        bytes32 node = _node(_node(_le64(p.genesisTime), _node(node10, p.stateBranch[1])), p.activeFields);
        node = _node(_node(p.blockBranch[1], _node(p.blockBranch[0], node)), p.blockBranch[2]);
        uint256 slotTime = uint256(p.genesisTime) + uint256(p.slot) * SECONDS_PER_SLOT;
        // An inactive field's root is zero, which reads as a zero time or slot: fields 0 to 3 must be active.
        if (
            node != _beaconRoot(p.timestamp) || (uint8(p.activeFields[0]) & 0x0f) != 0x0f
                || p.genesisValidatorsRoot != GENESIS_VALIDATORS_ROOT || slotTime >= p.timestamp
        ) {
            revert BadBeaconProof();
        }
        // Before the pinned fork's activation: says nothing about the chain now.
        if (p.epoch < FORK_EPOCH) revert StaleFork();
        pinned = p.currentVersion == FORK_VERSION && p.epoch == FORK_EPOCH;
        if (pinned) {
            if (slotTime > forkCheckedAt) {
                forkCheckedAt = uint64(slotTime); // slotTime < p.timestamp < 2^64
                emit ForkChecked(uint64(slotTime));
            }
        } else {
            emit UnsupportedFork(p.currentVersion, p.epoch);
            if (block.timestamp < depositsEnd) _moveEnd(uint64(block.timestamp));
        }
    }

    /// Pays `recipient` for one burn output. Anyone may submit; the burn script fixes the recipient.
    function redeem(address payable recipient, BurnProof calldata burn, BlockRef calldata ref) external {
        if (recipient == address(0)) revert ZeroRecipient();
        _redeem(recipient, recipient, burn, ref);
    }

    /// Pays the caller's own burn output to `to`: for a recipient that refuses plain ETH, or would rather
    /// be paid elsewhere. The burn script names the recipient, so nobody else can redirect it.
    function redeemTo(address payable to, BurnProof calldata burn, BlockRef calldata ref) external {
        if (to == address(0)) revert ZeroRecipient();
        _redeem(msg.sender, to, burn, ref);
    }

    /// The scriptPubKey a burn for `recipient` must pay: OP_RETURN (0x6a), a direct push of 70 bytes (0x46), then
    /// BURN_TAG, BURN_CHAIN_ID big-endian, this escrow and the recipient: 72 bytes in all. Elements' default relay
    /// policy budgets data-carrier bytes across the transaction; a node's settings can differ. Only this exact
    /// encoding redeems.
    function burnScriptPubKey(address recipient) public view returns (bytes memory) {
        return abi.encodePacked(hex"6a46", BURN_TAG, BURN_CHAIN_ID, address(this), recipient);
    }

    function isRedeemed(bytes32 txid, uint32 vout) external view returns (bool) {
        return redeemed[keccak256(abi.encodePacked(txid, vout))];
    }

    /// Before the first relayed batch lcTipTime is 0, and before the first fork proof forkCheckedAt is 0, so
    /// deposits start closed. Relaying and fork proofs can reopen deposits after a lapse, but nothing reopens
    /// them after depositsEnd.
    function _depositsOpen() internal view override returns (bool) {
        return block.timestamp < depositsEnd && forkCheckedAt != 0
            && block.timestamp <= uint256(forkCheckedAt) + MAX_FORK_CHECK_AGE && lcTipTime != 0
            && block.timestamp <= uint256(lcTipTime) + MAX_RELAY_LAG;
    }

    function _moveEnd(uint64 end) private {
        depositsEnd = end;
        emit DepositsEndMoved(end);
    }

    /// The beacon block root EIP-4788 holds for `timestamp`; it reverts for a timestamp it does not hold.
    function _beaconRoot(uint64 timestamp) private view returns (bytes32) {
        (bool ok, bytes memory root) = BEACON_ROOTS.staticcall(abi.encode(timestamp));
        if (!ok || root.length != 32) revert NoBeaconRoot();
        return bytes32(root);
    }

    /// An SSZ Merkle node.
    function _node(bytes32 left, bytes32 right) private pure returns (bytes32) {
        return sha256(abi.encodePacked(left, right));
    }

    /// The SSZ chunk of a uint64: little-endian, zero-padded on the right.
    function _le64(uint64 x) private pure returns (bytes32) {
        x = ((x & 0xff00ff00ff00ff00) >> 8) | ((x & 0x00ff00ff00ff00ff) << 8);
        x = ((x & 0xffff0000ffff0000) >> 16) | ((x & 0x0000ffff0000ffff) << 16);
        x = (x >> 32) | (x << 32);
        return bytes32(bytes8(x));
    }

    /// Checks the burn of `recipient` and pays its value to `to`, at most once per burn output.
    function _redeem(address recipient, address payable to, BurnProof calldata burn, BlockRef calldata ref) private {
        bytes32 txid = _txid(burn.transaction);
        bytes32 key = keccak256(abi.encodePacked(txid, burn.vout));
        if (redeemed[key]) revert AlreadyRedeemed();
        uint64 units = _burnedUnits(burn.transaction, burn.vout, recipient);
        uint32 height = _blockHeight(ref, ElementsParser.merkleRoot(txid, burn.branch, burn.position));
        if (uint256(height) + MIN_CONFIRMATIONS - 1 > lcTipHeight) revert TooFewConfirmations();
        uint256 amount = uint256(units) * UNIT_WEI;
        if (address(this).balance < amount) revert Insolvent();
        redeemed[key] = true;
        emit Redeemed(txid, burn.vout, recipient, to, units);
        _pay(to, amount);
    }

    /// The burn is already marked spent, so re-entering cannot pay it twice. The call gets all but 1/64
    /// of the remaining gas; if it fails, for any reason including too little gas from the submitter,
    /// the redemption reverts with it and the burn stays unspent.
    function _pay(address payable to, uint256 amount) private {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert PayoutFailed();
    }

    function _txid(bytes calldata raw) private pure returns (bytes32) {
        // A Merkle leaf preimage of exactly 64 bytes could be an inner node. No Elements transaction
        // is that short (one input and one explicit output already exceed it), and a valid burn
        // output alone is 116 bytes; the bound states that locally instead of relying on the parser.
        if (raw.length <= 64) revert ShortTransaction();
        return ElementsParser.sha256d(raw);
    }

    function _burnedUnits(bytes calldata raw, uint32 vout, address recipient) private view returns (uint64) {
        ElementsParser.ExplicitOutput memory out = ElementsParser.explicitOutput(raw, vout);
        if (out.asset != BRIDGE_ASSET) revert WrongAsset();
        if (out.value == 0) revert ZeroAmount();
        if (out.scriptHash != keccak256(burnScriptPubKey(recipient))) revert WrongBurnScript();
        return out.value;
    }
}
