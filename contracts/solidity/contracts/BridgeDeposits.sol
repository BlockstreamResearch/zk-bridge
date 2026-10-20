// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Deposits of the bridge escrow (BridgeEscrow): an append-only SHA-256 accumulator of deposit leaves.
///
///   recipient   SHA256(scriptPubKey) of a standard Liquid output script, which the deposit also carries
///               in its event. The claim leaf (contracts/simplicity/simf/claim.simf) pays the deposit to the
///               output whose script hashes to it, so any ordinary wallet address can receive.
///   gate        a deposit reverts DepositsClosed unless `_depositsOpen()`: BridgeEscrow admits deposits
///               only while its Liquid light client is current and the proof path to Liquid still holds
///               (its deposit window and fork check), so ETH is not locked into a bridge whose way to
///               Liquid or back nobody can complete.
///
/// The formulas the Liquid side checks:
///   leaf i      = sha256(DOMAIN || uint64 i || uint64 units || bytes32 recipient)    80 bytes
///   tree        = depth-32 binary SHA-256 Merkle tree of leaves 0 .. 2^32 - 1; absent leaves are zero
///   accumulator = sha256(treeRoot || uint64 depositCount)                              storage slot 0
///   DOMAIN      = sha256("liquid-bridge-poc/deposit" || chainid || this)
/// The DOMAIN tag names the leaf layout; the chain id and this contract's address, part of DOMAIN, separate
/// its leaves from those of any other escrow.
///
/// This contract must be the first base of its deriving contract and declare its storage first: the
/// Ethereum light-client proof on Liquid reads storage slot 0.
abstract contract BridgeDeposits {
    error DepositsClosed();
    error BadRecipientScript();
    error BadDepositAmount();
    error DepositTreeFull();

    uint256 public constant TREE_DEPTH = 32;
    uint256 public constant UNIT_WEI = 10_000_000_000;
    // 0.001 ETH gives 100,000 units. A mint output below Liquid's relay threshold could leave that deposit
    // unclaimable; this floor is above the thresholds we know of. Whether Elements applies a dust rule to
    // explicit outputs of a non-policy asset was not checked.
    uint256 public constant MIN_UNITS = 100_000;
    // Elements MAX_MONEY. An explicit reissuance above it is consensus-invalid and would strand that deposit.
    uint256 public constant MAX_UNITS = 2_100_000_000_000_000;
    uint256 public constant MAX_DEPOSITS = 2 ** 32 - 1;

    /// secp256k1 field prime, for the P2TR key check.
    uint256 private constant SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Slot 0 is the only value the light-client update proof reads. Keep it the first variable.
    bytes32 public accumulator;
    uint64 public depositCount; // slot 1
    bytes32 public treeRoot; // slot 2
    bytes32[32] private branch; // slots 3 .. 34
    bytes32[32] private zeroHashes; // slots 35 .. 66
    bytes32 public immutable DOMAIN;

    event Deposit(
        uint64 indexed index, uint64 units, bytes32 recipient, bytes32 leaf, bytes32 accumulator, bytes scriptPubKey
    );

    constructor() {
        DOMAIN = sha256(abi.encodePacked("liquid-bridge-poc/deposit", block.chainid, address(this)));
        for (uint256 h = 0; h + 1 < TREE_DEPTH; h++) {
            zeroHashes[h + 1] = sha256(abi.encodePacked(zeroHashes[h], zeroHashes[h]));
        }
        bytes32 root = _root(0);
        treeRoot = root;
        accumulator = sha256(abi.encodePacked(root, uint64(0)));
    }

    /// Locks msg.value for `scriptPubKey` on Liquid testnet, whose wallet receives msg.value / UNIT_WEI units
    /// of the bridge asset as an explicit output once the deposit is proven to Liquid and claimed.
    function deposit(bytes calldata scriptPubKey) external payable returns (uint64 index) {
        if (!_depositsOpen()) revert DepositsClosed();
        bytes32 recipient = recipientOf(scriptPubKey);
        uint64 units = _unitsOf(msg.value);
        // The insertion runs in its own frame, so that the event's calldata argument stays within the
        // unoptimized compiler's reach of 16 stack slots.
        bytes32 leaf;
        bytes32 acc;
        (index, leaf, acc) = _append(units, recipient);
        emit Deposit(index, units, recipient, leaf, acc, scriptPubKey);
    }

    /// The units of a deposit of `value` wei, which must be a whole number of units within the bounds.
    function _unitsOf(uint256 value) private pure returns (uint64) {
        if (value % UNIT_WEI != 0) revert BadDepositAmount();
        uint256 units = value / UNIT_WEI;
        if (units < MIN_UNITS || units > MAX_UNITS) revert BadDepositAmount();
        return uint64(units); // MAX_UNITS < 2^64
    }

    /// Appends leaf (depositCount, units, recipient) and stores the new count, root and accumulator.
    function _append(uint64 units, bytes32 recipient) private returns (uint64 index, bytes32 leaf, bytes32 acc) {
        uint256 count = depositCount;
        if (count >= MAX_DEPOSITS) revert DepositTreeFull();
        index = uint64(count);
        leaf = leafOf(index, units, recipient);
        // Insert: update the one stored branch node that changes (Ethereum deposit contract algorithm).
        uint256 size = count + 1;
        bytes32 node = leaf;
        for (uint256 h = 0; h < TREE_DEPTH; h++) {
            if ((size & 1) == 1) {
                branch[h] = node;
                break;
            }
            node = sha256(abi.encodePacked(branch[h], node));
            size >>= 1;
        }
        depositCount = uint64(count + 1);
        bytes32 root = _root(count + 1);
        treeRoot = root;
        acc = sha256(abi.encodePacked(root, uint64(count + 1)));
        accumulator = acc;
    }

    /// The committed recipient of a deposit to `scriptPubKey`: SHA256 of the script, which must be one of the
    /// standard forms a wallet can spend: P2PKH, P2SH, P2WPKH, P2WSH, or P2TR with a valid x-only key.
    /// Everything else is refused: an empty or OP_RETURN script would be a fee or a burn, and a future
    /// witness version is spendable by anyone today.
    function recipientOf(bytes calldata scriptPubKey) public view returns (bytes32) {
        bytes calldata s = scriptPubKey;
        uint256 n = s.length;
        bool standard = (n == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac) // P2PKH
            || (n == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) // P2SH
            || (n == 22 && s[0] == 0x00 && s[1] == 0x14) // P2WPKH
            || (n == 34 && s[0] == 0x00 && s[1] == 0x20) // P2WSH
            || (n == 34 && s[0] == 0x51 && s[1] == 0x20 && _isXOnlyKey(uint256(bytes32(s[2:34])))); // P2TR
        if (!standard) revert BadRecipientScript();
        return sha256(s);
    }

    function leafOf(uint64 index, uint64 units, bytes32 recipient) public view returns (bytes32) {
        return sha256(abi.encodePacked(DOMAIN, index, units, recipient));
    }

    /// The root a 32-sibling branch gives for `leaf` at `index`; the Liquid claim covenant computes the
    /// same: bit h of the index is 0 when the running node is the left child at height h.
    function rootFromBranch(bytes32 leaf, uint64 index, bytes32[32] calldata siblings)
        external
        pure
        returns (bytes32 node)
    {
        node = leaf;
        uint256 i = index;
        for (uint256 h = 0; h < TREE_DEPTH; h++) {
            node = (i & 1) == 0
                ? sha256(abi.encodePacked(node, siblings[h]))
                : sha256(abi.encodePacked(siblings[h], node));
            i >>= 1;
        }
    }

    /// Whether deposits are accepted now.
    function _depositsOpen() internal view virtual returns (bool);

    function _root(uint256 size) internal view returns (bytes32 node) {
        for (uint256 h = 0; h < TREE_DEPTH; h++) {
            if ((size & 1) == 1) {
                node = sha256(abi.encodePacked(branch[h], node));
            } else {
                node = sha256(abi.encodePacked(node, zeroHashes[h]));
            }
            size >>= 1;
        }
    }

    /// x is a BIP340 x-only key: x < p and x^3 + 7 is a square mod p (Euler's criterion, through the modexp
    /// precompile). x^3 + 7 is never 0 mod p, since secp256k1 has no point of order 2.
    function _isXOnlyKey(uint256 x) private view returns (bool) {
        if (x >= SECP_P) return false;
        uint256 rhs = addmod(mulmod(mulmod(x, x, SECP_P), x, SECP_P), 7, SECP_P);
        (bool ok, bytes memory r) = address(0x05)
            .staticcall(abi.encodePacked(uint256(32), uint256(32), uint256(32), rhs, (SECP_P - 1) / 2, SECP_P));
        return ok && r.length == 32 && uint256(bytes32(r)) == 1;
    }
}
