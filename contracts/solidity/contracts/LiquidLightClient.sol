// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ElementsParser} from "./ElementsParser.sol";

/// A Liquid light client that follows Liquid's signed header chain epoch by epoch, including DynaFed
/// changes of the block-signing script, so that each height is trusted only under the keys that were
/// current at that height.
///
/// Elements rules it mirrors (Elements 23: block_proof.cpp CheckProof, dynafed.cpp
/// NextBlockIsParameterTransition, validation.cpp ContextualCheckDynaFedHeader):
///   epoch e         heights e*L .. e*L + L - 1, L = EPOCH_LENGTH (Liquid testnet 1000, mainnet 20160)
///   signing         THRESHOLD keys of the epoch's witness script sign the block hash (ECDSA, in
///                   OP_CHECKMULTISIG key order); the epoch's signblockscript is P2WSH(witness script)
///   current params  every header of epoch e commits to epoch e's signblockscript
///   transition      epoch e+1 uses the signblockscript of the proposal that at least
///                   T = 4L/5 headers of epoch e carry; otherwise epoch e's. Null never wins.
///                   L must be a multiple of 5, as on every Liquid network (and regtest's 10): then
///                   (4 * L) / 5 and L - L / 5, the two readings of Elements' threshold, are equal.
///
/// Relaying. `submitHeaders` takes a batch: consecutive headers within one epoch, the first being the
/// child of the stored tip. THRESHOLD keys of that epoch must sign the batch's last header. Its hash
/// commits to every earlier header of the batch, so one signature set endorses the whole batch. Each
/// batch stores a commitment to its headers' transaction Merkle roots, which `_blockHeight` opens. So
/// every height is accepted once, in order, under the keys of its own epoch. After a key change,
/// headers under the retired keys are never accepted at any later height.
///
/// Votes. Elements tallies proposals by `CalculateRoot`, a fast Merkle root built from the bare SHA-256
/// compression function, which the SHA-256 precompile cannot compute. This contract tallies the exact
/// proposal serialization instead:
///   one serialization has >= T votes   its root has >= T votes; 2T > L makes it the unique winner
///   fewer than T non-null proposals    no root can reach T, so the script is unchanged
///   otherwise                          undecidable here: the next epoch reverts AmbiguousTally
/// Counting serializations can only undercount a root, never overcount it, and every non-null vote
/// counts toward `nonNullVotes` whatever its encoding. So the client never follows a transition
/// Elements did not make and never misses one Elements made. The cost is liveness: at least T non-null
/// votes with no single serialization reaching T (for example one parameter set proposed in two
/// encodings) stops the client instead of letting it guess.
///
/// Assumptions (besides SHA-256 and keccak256 collision resistance and ECDSA unforgeability):
///   L1  while its keys are current, each epoch's signing set signs only valid blocks of one chain,
///       never two headers at one height
///   L2  the checkpoint is Liquid's: the hash of the last block of an epoch and the witness script of
///       the next epoch (weak subjectivity, like the Ethereum anchor in the Liquid covenant)
///   L3  the keys of epoch e stay honest until every height of epoch e has been relayed, even after
///       Liquid has retired them. The client verifies each batch under the held epoch's keys and cannot
///       tell a late honest relay from a late forgery, so keys that sign a fork of e's unrelayed heights
///       can give it fake Merkle roots (unbacked burns) and, with T votes, move the client onto keys of
///       their choosing (test/LiquidLightClient.t.sol pins this boundary). No time bound helps:
///       header times are the signers' own. Prompt relaying of every epoch to its end keeps the window
///       short; BridgeEscrow closes deposits while relaying lags.
/// Liveness: someone must relay every epoch. An unsupported signing script after a transition, an
/// ambiguous tally, or a fork at the relayed tip (only possible if L1 fails) stops the client
/// permanently: there is no admin path.
abstract contract LiquidLightClient {
    error BadEpochLength();
    error BadCheckpoint();
    error BadWitnessScript();
    error BadKey();
    error EmptyBatch();
    error CrossesEpoch();
    error BrokenChain();
    error WrongSignblockscript();
    error AmbiguousTally();
    error MissingWitnessScript();
    error UnexpectedWitnessScript();
    error WrongWitnessScript();
    error WrongSignatureCount();
    error BadSignature();
    error UnknownBatch();
    error BadBlockRef();
    error NotInBatch();

    /// The trusted starting point (assumption L2).
    struct Checkpoint {
        uint32 epochLength; // Elements' dynamic_epoch_length of the network
        uint32 height; // the last height of an epoch
        bytes32 hash; // that block's hash, internal byte order (the reverse of the displayed hash)
        bytes witnessScript; // the next epoch's block-signing witness script
        uint256[] keyY; // y coordinate of each key of witnessScript, in script order
    }

    /// One block-signing signature over a block hash: the (r, s) of a DER signblock witness signature.
    struct Signature {
        bytes32 r;
        bytes32 s;
    }

    /// A block of a stored batch: its index in the batch and the batch-tree path, leaf level first.
    struct BlockRef {
        uint256 batch;
        uint256 index;
        bytes32[] path;
    }

    /// `root` is a keccak256 Merkle root over leaves keccak256(merkleRoot of each header) in height
    /// order, padded with zero leaves to the next power of two.
    struct Batch {
        uint32 firstHeight;
        uint32 count;
        bytes32 root;
    }

    /// secp256k1 field prime.
    uint256 private constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    uint32 public immutable EPOCH_LENGTH;
    uint32 public immutable VOTE_THRESHOLD;

    bytes32 public lcTipHash;
    uint32 public lcTipHeight;
    /// nTime of the tip header (zero until the first batch): a liveness beacon for interfaces.
    uint32 public lcTipTime;
    /// The epoch whose signing keys and vote tally are held. (lcTipHeight + 1) / L is this epoch, or the
    /// next one once its last height is covered.
    uint32 public epoch;
    uint32 public nonNullVotes;
    /// keccak256 of the signblockscript of `epoch`.
    bytes32 public signblockscriptHash;
    /// keccak256 of the signblockscript of `epoch`'s winning proposal; zero while none has T votes.
    /// keccak256 of any byte string is nonzero, so zero cannot be a real winner.
    bytes32 public winnerSignblockscriptHash;
    uint256 public signingThreshold;
    address[] private signers; // Ethereum addresses of the witness script's keys, in script order
    mapping(bytes32 => uint32) private votes; // keccak256(abi.encode(epoch, proposal hash)) => count
    Batch[] private batches;

    event HeadersAccepted(uint256 indexed batch, uint32 firstHeight, uint32 count, bytes32 root, bytes32 tipHash);
    event SigningScriptChanged(uint32 indexed newEpoch, bytes32 newSignblockscriptHash);

    constructor(Checkpoint memory cp) {
        uint256 length = cp.epochLength;
        if (length == 0 || length % 5 != 0) revert BadEpochLength();
        // T = 4L/5 exactly, so 2T > L: at most one proposal reaches T and the tally order cannot matter.
        uint256 threshold = (length / 5) * 4;
        if (cp.height % length != length - 1 || cp.hash == bytes32(0)) revert BadCheckpoint();
        EPOCH_LENGTH = cp.epochLength;
        VOTE_THRESHOLD = uint32(threshold);
        epoch = uint32((uint256(cp.height) + 1) / length);
        lcTipHash = cp.hash;
        lcTipHeight = cp.height;
        signblockscriptHash = _p2wsh(cp.witnessScript);
        _setSigners(cp.witnessScript, cp.keyY);
    }

    /// Accepts `headers`, hash-form DynaFed headers (no signblock witness), as the next heights.
    /// `witnessScript` and `keyY` must be given exactly when the batch starts an epoch whose
    /// signblockscript differs from the previous epoch's, and must be empty otherwise.
    function submitHeaders(
        bytes[] calldata headers,
        Signature[] calldata sigs,
        bytes calldata witnessScript,
        uint256[] calldata keyY
    ) external returns (uint256 batch) {
        uint256 n = headers.length;
        if (n == 0) revert EmptyBatch();
        uint256 first = uint256(lcTipHeight) + 1;
        _openEpoch(first, first + n - 1, witnessScript, keyY);
        (bytes32 tip, uint32 tipTime, bytes32 root) = _chain(headers, first);
        _verifyTip(tip, sigs);

        // _chain matched every height to first + i, a uint32 header field, so these casts are exact.
        lcTipHash = tip;
        lcTipHeight = uint32(first + n - 1);
        lcTipTime = tipTime;
        batch = batches.length;
        batches.push(Batch(uint32(first), uint32(n), root));
        emit HeadersAccepted(batch, uint32(first), uint32(n), root, tip);
    }

    function batchCount() external view returns (uint256) {
        return batches.length;
    }

    function batchAt(uint256 i) external view returns (Batch memory) {
        return batches[i];
    }

    /// The signing keys' Ethereum addresses for `epoch`, in witness-script order.
    function federation() external view returns (address[] memory) {
        return signers;
    }

    /// The height of the block whose transaction Merkle root is `merkleRoot`, if `ref` opens it in a
    /// stored batch. Every stored height is covered by a signed header chain (see the contract notes).
    function _blockHeight(BlockRef calldata ref, bytes32 merkleRoot) internal view returns (uint32) {
        if (ref.batch >= batches.length) revert UnknownBatch();
        Batch memory b = batches[ref.batch];
        if (ref.index >= b.count || ref.path.length != _log2(_ceilPow2(b.count))) revert BadBlockRef();
        bytes32 node = keccak256(abi.encodePacked(merkleRoot));
        uint256 i = ref.index;
        for (uint256 d = 0; d < ref.path.length; d++) {
            node = (i & 1) == 0
                ? keccak256(abi.encodePacked(node, ref.path[d]))
                : keccak256(abi.encodePacked(ref.path[d], node));
            i >>= 1;
        }
        if (node != b.root) revert NotInBatch();
        // index < count <= 2^32 - 1 and firstHeight + count - 1 was a stored uint32 height.
        return b.firstHeight + uint32(ref.index);
    }

    /// Requires heights first .. last to lie in one epoch and makes it the held epoch.
    function _openEpoch(uint256 first, uint256 last, bytes calldata witnessScript, uint256[] calldata keyY) private {
        uint256 length = EPOCH_LENGTH;
        if (first / length != last / length) revert CrossesEpoch();
        // `first` is the stored tip's child, so first / length is `epoch` or `epoch` + 1 (see `epoch`).
        if (first / length != epoch) {
            _enterNextEpoch(witnessScript, keyY);
        } else if (witnessScript.length != 0 || keyY.length != 0) {
            revert UnexpectedWitnessScript();
        }
    }

    /// Checks that `headers` extend the stored tip at heights first, first + 1, ... under the held
    /// epoch's signblockscript, counts their votes, and returns the last hash and time and the
    /// batch root.
    function _chain(bytes[] calldata headers, uint256 first)
        private
        returns (bytes32 prev, uint32 tipTime, bytes32 root)
    {
        bytes32 script = signblockscriptHash;
        prev = lcTipHash;
        bytes32[] memory leaves = new bytes32[](_ceilPow2(headers.length));
        for (uint256 i = 0; i < headers.length; i++) {
            ElementsParser.Header memory h = ElementsParser.header(headers[i]);
            if (h.prev != prev || h.height != first + i) revert BrokenChain();
            if (h.signblockscriptHash != script) revert WrongSignblockscript();
            if (h.proposalHash != bytes32(0)) _vote(h.proposalHash, h.proposedSignblockscriptHash);
            leaves[i] = keccak256(abi.encodePacked(h.merkleRoot));
            prev = h.hash;
            tipTime = h.time;
        }
        root = _batchRoot(leaves);
    }

    /// Decides the signing script of epoch + 1 from epoch's tally and moves to it.
    function _enterNextEpoch(bytes calldata witnessScript, uint256[] calldata keyY) private {
        bytes32 next = signblockscriptHash;
        if (winnerSignblockscriptHash != bytes32(0)) {
            next = winnerSignblockscriptHash;
        } else if (nonNullVotes >= VOTE_THRESHOLD) {
            revert AmbiguousTally();
        }
        uint32 e = epoch + 1;
        if (next != signblockscriptHash) {
            if (witnessScript.length == 0) revert MissingWitnessScript();
            if (_p2wsh(witnessScript) != next) revert WrongWitnessScript();
            _setSigners(witnessScript, keyY);
            signblockscriptHash = next;
            emit SigningScriptChanged(e, next);
        } else if (witnessScript.length != 0 || keyY.length != 0) {
            revert UnexpectedWitnessScript();
        }
        epoch = e;
        nonNullVotes = 0;
        winnerSignblockscriptHash = bytes32(0);
    }

    function _vote(bytes32 proposal, bytes32 proposedScript) private {
        nonNullVotes += 1;
        uint32 c = ++votes[keccak256(abi.encode(epoch, proposal))];
        // Only one serialization can reach T in an epoch (2T > L), so this is set at most once.
        if (c == VOTE_THRESHOLD) winnerSignblockscriptHash = proposedScript;
    }

    /// OP_CHECKMULTISIG's matching rule over recovered addresses: each signature must match a key
    /// after the key the previous signature matched. A DER signature carries no recovery id, so both
    /// are tried; ecrecover returns zero on failure and no stored key is zero.
    function _verifyTip(bytes32 blockHash, Signature[] calldata sigs) private view {
        if (sigs.length != signingThreshold) revert WrongSignatureCount();
        address[] memory keys = signers;
        uint256 k = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            address a = ecrecover(blockHash, 27, sigs[i].r, sigs[i].s);
            address b = ecrecover(blockHash, 28, sigs[i].r, sigs[i].s);
            while (k < keys.length && keys[k] != a && keys[k] != b) k++;
            if (k == keys.length) revert BadSignature();
            k++;
        }
    }

    function _setSigners(bytes memory witnessScript, uint256[] memory keyY) private {
        (uint256 m, uint256 n, uint256 firstKey) = _parseWitnessScript(witnessScript);
        if (keyY.length != n) revert BadKey();
        delete signers;
        for (uint256 i = 0; i < n; i++) {
            signers.push(_keyAddress(witnessScript, firstKey + 34 * i, keyY[i]));
        }
        signingThreshold = m;
    }

    /// keccak256 of P2WSH(witnessScript) = 0x0020 || SHA256(witnessScript).
    function _p2wsh(bytes memory witnessScript) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"0020", sha256(witnessScript)));
    }

    /// Returns (m, n, offset of key 0's prefix byte); key i's prefix is at that offset + 34 * i.
    /// Accepted forms: `<key> OP_CHECKSIG` and `OP_m <key>... OP_n OP_CHECKMULTISIG`, 1 <= m <= n <= 16,
    /// compressed keys only. Anything else, such as a timelocked or Taproot script, is rejected: the
    /// client then cannot follow that epoch (fails closed).
    function _parseWitnessScript(bytes memory s) private pure returns (uint256 m, uint256 n, uint256 firstKey) {
        if (s.length == 35 && s[0] == 0x21 && s[34] == 0xac) return (1, 1, 1);
        if (s.length < 37 || (s.length - 3) % 34 != 0) revert BadWitnessScript();
        n = (s.length - 3) / 34;
        m = uint8(s[0]);
        if (m < 0x51 || m > 0x60 || n > 16) revert BadWitnessScript();
        m -= 0x50;
        if (m > n || uint8(s[s.length - 2]) != 0x50 + n || s[s.length - 1] != 0xae) revert BadWitnessScript();
        for (uint256 i = 0; i < n; i++) {
            if (s[1 + 34 * i] != 0x21) revert BadWitnessScript();
        }
        return (m, n, 2);
    }

    /// The Ethereum address of the compressed key at `at`, given its y coordinate. Checking y on the
    /// curve and against the prefix parity stands in for a modular square root.
    function _keyAddress(bytes memory s, uint256 at, uint256 y) private pure returns (address key) {
        bytes1 prefix = s[at];
        uint256 x;
        for (uint256 i = 0; i < 32; i++) {
            x = (x << 8) | uint8(s[at + 1 + i]);
        }
        if ((prefix != 0x02 && prefix != 0x03) || x >= P || y >= P) revert BadKey();
        if (mulmod(y, y, P) != addmod(mulmod(mulmod(x, x, P), x, P), 7, P)) revert BadKey();
        if (((y & 1) == 1) != (prefix == 0x03)) revert BadKey();
        key = address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
        if (key == address(0)) revert BadKey();
    }

    /// Reduces `level` in place to its Merkle root; level.length is a power of two.
    function _batchRoot(bytes32[] memory level) private pure returns (bytes32) {
        for (uint256 len = level.length; len > 1; len >>= 1) {
            for (uint256 j = 0; j < len / 2; j++) {
                level[j] = keccak256(abi.encodePacked(level[2 * j], level[2 * j + 1]));
            }
        }
        return level[0];
    }

    function _ceilPow2(uint256 n) private pure returns (uint256 p) {
        p = 1;
        while (p < n) p <<= 1;
    }

    function _log2(uint256 p) private pure returns (uint256 d) {
        while (p > 1) {
            p >>= 1;
            d++;
        }
    }
}
