// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Strict parsers for the three Elements (Liquid) encodings the redemption path reads. Every parser
/// consumes its input exactly and reverts on any byte it does not recognise, so a caller never acts
/// on a partial or ambiguous parse.
///
/// Encodings, as serialized by Elements 23 (primitives/transaction.h, primitives/block.h, dynafed.h):
///
///   transaction, txid form   version u32le | flags u8 (always 0 in this form) | vin | vout | locktime u32le
///     input                  prevout txid (32) | prevout n u32le | scriptSig | sequence u32le | [issuance]
///                            issuance is present iff n != 0xffffffff and bit 31 of n is set:
///                            blinding nonce (32) | entropy (32) | amount (value) | inflation keys (value)
///     output                 asset | value | nonce | scriptPubKey
///     asset                  0x00 null | 0x01 explicit asset id (32) | 0x0a, 0x0b commitment (32)
///     value                  0x00 null | 0x01 explicit amount u64be  | 0x08, 0x09 commitment (32)
///     nonce                  0x00 null | 0x01 explicit (32)          | 0x02, 0x03 commitment (32)
///   DynaFed header, hash form
///                            version u32le with bit 31 set | prev block (32) | merkle root (32) | time u32le
///                            | height u32le | current params | proposed params
///     params                 0x00 null
///                            | 0x01 compact: signblockscript | witness limit u32le | elided root (32)
///                            | 0x02 full:    signblockscript | witness limit u32le | fedpeg program
///                                            | fedpegscript | extension space (vector of byte vectors)
///   byte vectors are CompactSize-prefixed; sizes must be minimally encoded, as Elements requires.
///
/// txid = SHA256d(transaction), block hash = SHA256d(header), Merkle parent = SHA256d(left || right),
/// all in internal byte order: the reverse of the hex that explorers display.
library ElementsParser {
    error Truncated();
    error NonCanonicalSize();
    error BadPrefix();
    error WitnessFlag();
    error NoInputs();
    error NoOutputs();
    error NoSuchOutput();
    error NotExplicit();
    error TrailingBytes();
    error NotDynafed();
    error NullCurrentParams();
    error BadParamsType();
    error BadBranch();

    uint32 private constant ISSUANCE_FLAG = 1 << 31;
    uint32 private constant NULL_INDEX = type(uint32).max;
    uint32 private constant DYNAFED_FLAG = 1 << 31;

    /// The explicit asset, amount and scriptPubKey hash of one transaction output.
    struct ExplicitOutput {
        bytes32 asset; // internal byte order, as serialized
        uint64 value;
        bytes32 scriptHash; // keccak256(scriptPubKey)
    }

    /// The fields of a DynaFed header the bridge reads.
    struct Header {
        bytes32 hash; // SHA256d of the hash-form serialization
        bytes32 prev;
        bytes32 merkleRoot;
        uint32 height;
        bytes32 signblockscriptHash; // keccak256 of the current params' signblockscript
        uint32 time;
        bytes32 proposalHash; // keccak256 of the serialized proposed params, type byte included; 0 if null
        bytes32 proposedSignblockscriptHash; // keccak256 of the proposed signblockscript; 0 if null
    }

    function sha256d(bytes calldata b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(b)));
    }

    function sha256dPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(abi.encodePacked(left, right))));
    }

    /// Parses a whole transaction in txid form and returns output `vout`, which must have an
    /// explicit asset and an explicit value. Other outputs may use any valid encoding.
    function explicitOutput(bytes calldata raw, uint256 vout) internal pure returns (ExplicitOutput memory out) {
        _need(raw, 0, 5);
        if (raw[4] != 0x00) revert WitnessFlag();
        uint256 p = 5;
        uint256 count;
        (count, p) = _compactSize(raw, p);
        if (count == 0) revert NoInputs();
        for (uint256 i = 0; i < count; i++) {
            p = _skipInput(raw, p);
        }
        (count, p) = _compactSize(raw, p);
        if (count == 0) revert NoOutputs();
        if (vout >= count) revert NoSuchOutput();
        for (uint256 i = 0; i < count; i++) {
            if (i == vout) {
                (out, p) = _readExplicitOutput(raw, p);
            } else {
                p = _skipOutput(raw, p);
            }
        }
        _need(raw, p, 4); // locktime
        if (p + 4 != raw.length) revert TrailingBytes();
    }

    /// Parses a DynaFed header in hash form (no signblock witness). The current params must not be null.
    function header(bytes calldata h) internal pure returns (Header memory out) {
        _need(h, 0, 76);
        if (_u32le(h, 0) & DYNAFED_FLAG == 0) revert NotDynafed();
        out.prev = bytes32(h[4:36]);
        out.merkleRoot = bytes32(h[36:68]);
        out.time = _u32le(h, 68);
        out.height = _u32le(h, 72);
        uint256 p = 76;
        _need(h, p, 1);
        if (h[p] == 0x00) revert NullCurrentParams();
        (out.signblockscriptHash, p) = _params(h, p);
        uint256 proposed = p;
        (out.proposedSignblockscriptHash, p) = _params(h, p);
        if (h[proposed] != 0x00) out.proposalHash = keccak256(h[proposed:p]);
        if (p != h.length) revert TrailingBytes();
        out.hash = sha256d(h);
    }

    /// The Merkle root of `leaf` at `position` with `branch` listed from the leaf upwards. Bit i of
    /// `position` is 1 when the running node is the right child at depth i. A position that does not
    /// fit in branch.length bits is rejected. Bitcoin's tree pairs the last node of an odd level with
    /// itself, so such a node verifies at both positions of the pair; callers must not key anything
    /// on the position.
    function merkleRoot(bytes32 leaf, bytes32[] calldata branch, uint256 position)
        internal
        pure
        returns (bytes32 node)
    {
        if (branch.length > 32 || position >> branch.length != 0) revert BadBranch();
        node = leaf;
        for (uint256 i = 0; i < branch.length; i++) {
            node = ((position >> i) & 1) == 0 ? sha256dPair(node, branch[i]) : sha256dPair(branch[i], node);
        }
    }

    function _skipInput(bytes calldata raw, uint256 p) private pure returns (uint256) {
        _need(raw, p, 36);
        uint32 n = _u32le(raw, p + 32);
        p = _skipBytes(raw, p + 36); // scriptSig
        _need(raw, p, 4); // sequence
        p += 4;
        if (n != NULL_INDEX && n & ISSUANCE_FLAG != 0) {
            _need(raw, p, 64); // blinding nonce, entropy
            p = _skipValue(raw, p + 64); // amount
            p = _skipValue(raw, p); // inflation keys
        }
        return p;
    }

    function _skipOutput(bytes calldata raw, uint256 p) private pure returns (uint256) {
        p = _skipCommitment(raw, p, 33, 0x0a, 0x0b); // asset
        p = _skipValue(raw, p);
        p = _skipCommitment(raw, p, 33, 0x02, 0x03); // nonce
        return _skipBytes(raw, p); // scriptPubKey
    }

    function _readExplicitOutput(bytes calldata raw, uint256 p)
        private
        pure
        returns (ExplicitOutput memory out, uint256)
    {
        _need(raw, p, 33 + 9);
        if (raw[p] != 0x01 || raw[p + 33] != 0x01) revert NotExplicit();
        out.asset = bytes32(raw[p + 1:p + 33]);
        out.value = uint64(bytes8(raw[p + 34:p + 42]));
        p = _skipCommitment(raw, p + 42, 33, 0x02, 0x03); // nonce
        uint256 len;
        (len, p) = _compactSize(raw, p);
        _need(raw, p, len);
        out.scriptHash = keccak256(raw[p:p + len]);
        return (out, p + len);
    }

    function _skipValue(bytes calldata b, uint256 p) private pure returns (uint256) {
        return _skipCommitment(b, p, 9, 0x08, 0x09);
    }

    /// Elements' CConfidentialCommitment: a prefix byte, then nothing (null), the explicit encoding
    /// (prefix 1) or a 33-byte commitment (prefix a or b), `explicitSize` and 33 counting the prefix.
    function _skipCommitment(bytes calldata b, uint256 p, uint256 explicitSize, bytes1 a, bytes1 c)
        private
        pure
        returns (uint256)
    {
        _need(b, p, 1);
        bytes1 prefix = b[p];
        uint256 size;
        if (prefix == 0x00) size = 1;
        else if (prefix == 0x01) size = explicitSize;
        else if (prefix == a || prefix == c) size = 33;
        else revert BadPrefix();
        _need(b, p, size);
        return p + size;
    }

    /// Returns the keccak256 of the params' signblockscript (zero for null params) and the end offset.
    function _params(bytes calldata h, uint256 p) private pure returns (bytes32 scriptHash, uint256) {
        _need(h, p, 1);
        bytes1 kind = h[p];
        p += 1;
        if (kind == 0x00) return (bytes32(0), p);
        if (kind != 0x01 && kind != 0x02) revert BadParamsType();
        uint256 len;
        (len, p) = _compactSize(h, p);
        _need(h, p, len + 4); // signblockscript, witness limit
        scriptHash = keccak256(h[p:p + len]);
        p += len + 4;
        if (kind == 0x01) {
            _need(h, p, 32); // elided root
            return (scriptHash, p + 32);
        }
        p = _skipBytes(h, p); // fedpeg program
        p = _skipBytes(h, p); // fedpegscript
        uint256 count;
        (count, p) = _compactSize(h, p); // extension space
        for (uint256 i = 0; i < count; i++) {
            p = _skipBytes(h, p);
        }
        return (scriptHash, p);
    }

    function _skipBytes(bytes calldata b, uint256 p) private pure returns (uint256) {
        uint256 len;
        (len, p) = _compactSize(b, p);
        _need(b, p, len);
        return p + len;
    }

    /// Bitcoin's CompactSize, rejecting non-minimal encodings as Elements' ReadCompactSize does.
    function _compactSize(bytes calldata b, uint256 p) private pure returns (uint256 v, uint256) {
        _need(b, p, 1);
        uint8 first = uint8(b[p]);
        if (first < 0xfd) return (first, p + 1);
        uint256 width;
        uint256 min;
        if (first == 0xfd) {
            (width, min) = (2, 0xfd);
        } else if (first == 0xfe) {
            (width, min) = (4, 0x10000);
        } else {
            (width, min) = (8, 0x100000000);
        }
        _need(b, p + 1, width);
        for (uint256 i = 0; i < width; i++) {
            v |= uint256(uint8(b[p + 1 + i])) << (8 * i);
        }
        if (v < min) revert NonCanonicalSize();
        return (v, p + 1 + width);
    }

    function _u32le(bytes calldata b, uint256 p) private pure returns (uint32) {
        _need(b, p, 4);
        return uint32(uint8(b[p])) | (uint32(uint8(b[p + 1])) << 8) | (uint32(uint8(b[p + 2])) << 16)
            | (uint32(uint8(b[p + 3])) << 24);
    }

    /// Bounds check before every read. Offsets and lengths come from calldata of at most a few
    /// megabytes and CompactSize values below 2^64, so `p + n` cannot overflow a uint256.
    function _need(bytes calldata b, uint256 p, uint256 n) private pure {
        if (p + n > b.length) revert Truncated();
    }
}
