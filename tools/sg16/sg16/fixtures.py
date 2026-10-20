"""Deterministic local test parameters for the update leaf (no network data).

The entropy and token blinding factors are synthetic: SHA256 of fixed test labels.  Genesis and fee asset are
the Liquid testnet values (display hex reversed to internal order).
"""
import hashlib

LIQUID_TESTNET_GENESIS_DISPLAY = 'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1'
LIQUID_TESTNET_LBTC_DISPLAY = '144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49'


def h(label):
    return hashlib.sha256(label.encode()).digest()


def internal(display_hex):
    """Display (explorer) hex of a txid, block hash or asset id -> internal byte order hex."""
    return bytes.fromhex(display_hex)[::-1].hex()


def config(entropy=None, genesis=None, fee_asset=None):
    """A tools/sg16-harness configuration (src/bridge.rs `Config`)."""
    return dict(genesis=genesis or internal(LIQUID_TESTNET_GENESIS_DISPLAY),
                entropy=entropy or h('sg16 test entropy').hex(),
                fee_asset=fee_asset or internal(LIQUID_TESTNET_LBTC_DISPLAY),
                abf_a=h('sg16 test token blinding A').hex(),
                abf_b=h('sg16 test token blinding B').hex())
