"""Costs (mWU) of the Elements jets the update leaf may use, added to the reference generator's table.

Values from rust-simplicity's Elements jet table (src/jet/init/elements.rs).  The local checkout pins
rust-simplicity 0.8.0; every jet the reference generator already lists has the same cost there as in its
0.9.0 table (fe_multiply 808, scalar_multiply 774, sig_all_hash 133, sha_256_block 771, ...).  The harness
runs simplicity-lang =0.9.0 and the tests compare every prediction with its bound, so a changed cost would
show up as a mismatch, not as a silent error.
"""
from .ref import REF  # noqa: F401  (puts groth on sys.path)
from groth.sym import JET_COST

ELEMENTS_JETS = {
    # introspection
    'current_index': 88, 'num_inputs': 86, 'num_outputs': 79, 'current_prev_outpoint': 156,
    'current_asset': 171, 'genesis_block_hash': 148, 'script_cmr': 136, 'internal_key': 152,
    'tappath': 83, 'tappath_hash': 143, 'tapleaf_hash': 136,
    'output_script_hash': 151, 'output_asset': 170, 'output_amount': 298,
    'output_is_fee': 92, 'issuance': 91, 'issuance_asset': 151, 'current_issuance_asset_amount': 165,
    # taproot construction
    'build_tapleaf_simplicity': 1843, 'build_tapbranch': 2563, 'build_taptweak': 92813,
    # hashing and comparison
    'sha_256_ctx_8_add_2': 661, 'sha_256_ctx_8_add_4': 645, 'sha_256_ctx_8_add_8': 674, 'sha_256_ctx_8_add_16': 747,
    'sha_256_ctx_8_add_32': 896, 'sha_256_ctx_8_finalize': 835, 'eq_32': 88,
}
for _name, _cost in ELEMENTS_JETS.items():
    assert JET_COST.get(_name, _cost) == _cost, f'conflicting cost for {_name}'
    JET_COST[_name] = _cost
