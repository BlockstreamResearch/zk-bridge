"""SSZ for BridgeEscrow.checkFork: the hash tree roots its beacon-state proof needs, and the proof itself.

checkFork (contracts/solidity/contracts/BridgeEscrow.sol) recomputes the EIP-4788 beacon block root for `timestamp` from BeaconState
fields 0 to 3 and three state nodes and three block nodes:

  state  A ProgressiveContainer (EIP-7495), as Sepolia's BeaconState is from Gloas on: node 2 is the progressive
         tree of its field roots (EIP-7916), node 3 the active-fields bits. Field 0 (genesis_time) is node 4, fields
         1 to 4 (genesis_validators_root, slot, fork, latest_block_header) are nodes 40 to 43 under node 10, and
         fields 5 on are under node 11. The proof gives nodes 43 and 11 (stateBranch) and 3 (activeFields).
  block  BeaconBlockHeader(slot, proposer_index, parent_root, state_root, body_root): state_root is node 11.
         Its branch is nodes 10 (parent_root), 4 (slot, proposer_index) and 3 (body_root and padding).

Where the values come from:

  fields 0-3   The beacon API: genesis_time and genesis_validators_root from /eth/v1/beacon/genesis, the fork from
               /eth/v1/beacon/states/{id}/fork, and the slot from the header.
  field 4      latest_block_header of the state after a block is that block's header with a zero state_root.
  nodes 11, 3  A light-client branch of the same state: a finality update's finality_branch (the root of
               finalized_checkpoint, field 20, node 735) or a bootstrap's current_sync_committee_branch (field 22,
               node 2945). The branch also fixes nodes 4 and 10.

So no field type past field 4 is needed, and no state download. `fork_proof` checks the sources against each other:
the branch must reach the header's state_root, and fields 0 to 4 must give the branch's nodes 4 and 10. A wrong
fork, genesis or header therefore gives an error, not a wrong proof; checkFork recomputes the root on chain in any
case, from the EIP-4788 root that fork_proof.py requires to equal the header's.

The tree a branch proves is not assumed either. STATE_LAYOUTS lists the shapes a BeaconState has had or might take:
Containers of 32 to 256 leaves, and the ProgressiveContainer. A branch's length leaves one or two; its hashes then
pick the one whose path reaches the header's state_root, or none. checkFork hashes only the progressive one
(CHECK_FORK_LAYOUT). For any other, and for a state whose active-fields bits leave one of fields 0 to 3 inactive,
`fork_proof` raises UnprovableState instead of building a proof, since no proof of that state can satisfy the
contract.

Sizes are the mainnet preset's, which Sepolia uses. Standard library only.
"""
import hashlib

SECONDS_PER_SLOT = 12
SYNC_COMMITTEE_SIZE = 512

# The BeaconState fields the light-client branches prove: finalized_checkpoint, a Checkpoint(epoch, root), and
# current_sync_committee.
FINALIZED_CHECKPOINT = 20
CURRENT_SYNC_COMMITTEE = 22


def container_gindex(width):
    """Field i of a Container whose field roots fill a `width`-leaf tree."""
    return lambda i: width + i


def progressive_gindex(i):
    """Field i of a ProgressiveContainer (EIP-7495). Node 2 is the progressive tree of the field roots (EIP-7916),
    node 3 the active-fields mix-in. Each node on that tree's spine has a subtree of 1, 4, 16, ... fields on its
    left and the rest of the spine on its right (the consensus specs' merkleize_progressive, EIP-7916)."""
    spine, first, width = 2, 0, 1
    while i >= first + width:
        spine, first, width = 2 * spine + 1, first + width, 4 * width
    return 2 * spine * width + i - first


# Each BeaconState tree shape a light-client branch may come from, as field index -> generalized index: a Container
# of up to 32 fields (Altair to Deneb), 64 (Electra, Fulu), 128 or 256, or a ProgressiveContainer (Gloas).
STATE_LAYOUTS = {**{f'container{w}': container_gindex(w) for w in (32, 64, 128, 256)},
                 'progressive': progressive_gindex}
# The shape checkFork hashes.
CHECK_FORK_LAYOUT = 'progressive'
# The ProgressiveContainer nodes checkFork takes: field 4's root (latest_block_header), fields 5 on, the active-fields
# bits; and the two it recomputes, which a light-client branch fixes: field 0 (genesis_time) and fields 1 to 4.
LATEST_BLOCK_HEADER, LATER_FIELDS, ACTIVE_FIELDS, GENESIS_TIME, FIELDS_1_TO_4 = 43, 11, 3, 4, 10


def finalized_root_gindex(layout):
    return 2 * STATE_LAYOUTS[layout](FINALIZED_CHECKPOINT) + 1


def current_sync_committee_gindex(layout):
    return STATE_LAYOUTS[layout](CURRENT_SYNC_COMMITTEE)


class UnprovableState(ValueError):
    """The state is in a tree shape that checkFork does not hash, so it has no checkFork proof."""


def sha(b):
    return hashlib.sha256(b).digest()


ZERO = [bytes(32)]  # ZERO[d]: the root of a depth-d tree of zero chunks
for _ in range(64):
    ZERO.append(sha(ZERO[-1] + ZERO[-1]))


def node(left, right):
    return sha(left + right)


def chunk(b):
    """A value of at most 32 bytes as one chunk, zero-padded on the right."""
    if len(b) > 32:
        raise ValueError(f'{len(b)} bytes do not fit one chunk')
    return b + bytes(32 - len(b))


def u64(n):
    return chunk(n.to_bytes(8, 'little'))


def pack(b):
    return [chunk(b[i:i + 32]) for i in range(0, len(b), 32)]


def merkleize(chunks, limit=None):
    """SSZ merkleize: the chunks, zero-padded to the next power of two of `limit` (default: their count)."""
    count = len(chunks) if limit is None else limit
    if len(chunks) > count:
        raise ValueError(f'{len(chunks)} chunks exceed the limit {count}')
    depth = (count - 1).bit_length() if count > 1 else 0
    level = list(chunks)
    for d in range(depth):
        if len(level) % 2:
            level.append(ZERO[d])
        level = [node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0] if level else ZERO[depth]


def header_root(slot, proposer_index, parent_root, state_root, body_root):
    return merkleize([u64(slot), u64(proposer_index), parent_root, state_root, body_root])


def fork_root(previous_version, current_version, epoch):
    """Fork(previous_version, current_version, epoch)."""
    return merkleize([chunk(previous_version), chunk(current_version), u64(epoch)])


def sync_committee_root(pubkeys, aggregate_pubkey):
    if len(pubkeys) != SYNC_COMMITTEE_SIZE or any(len(k) != 48 for k in [*pubkeys, aggregate_pubkey]):
        raise ValueError(f'a sync committee is {SYNC_COMMITTEE_SIZE} 48-byte keys and an aggregate')
    return node(merkleize([merkleize(pack(k)) for k in pubkeys]), merkleize(pack(aggregate_pubkey)))


def walk(leaf, gindex, branch):
    """Every node a Merkle branch fixes, by generalized index: the leaf's ancestors and their siblings."""
    if len(branch) != gindex.bit_length() - 1:
        raise ValueError(f'a branch to node {gindex} needs {gindex.bit_length() - 1} nodes, not {len(branch)}')
    nodes, at = {gindex: leaf}, leaf
    for sibling in branch:
        nodes[gindex ^ 1] = sibling
        at = node(sibling, at) if gindex & 1 else node(at, sibling)
        gindex >>= 1
        nodes[gindex] = at
    return nodes


def hex_bytes(s, n):
    b = bytes.fromhex(s.removeprefix('0x'))
    if len(b) != n:
        raise ValueError(f'{s!r} is not {n} bytes')
    return b


def header_of(j):
    """A BeaconBlockHeader from beacon API JSON (a light-client header's `beacon`, or a header's `message`)."""
    return dict(slot=int(j['slot']), proposer_index=int(j['proposer_index']),
                parent_root=hex_bytes(j['parent_root'], 32), state_root=hex_bytes(j['state_root'], 32),
                body_root=hex_bytes(j['body_root'], 32))


def root_of(h):
    return header_root(h['slot'], h['proposer_index'], h['parent_root'], h['state_root'], h['body_root'])


def chain_of(genesis, fork):
    """Fields 0, 1 and 3 of a state, from the beacon API's /eth/v1/beacon/genesis and /eth/v1/beacon/states/{id}/fork
    responses."""
    g, f = genesis['data'], fork['data']
    return dict(genesis_time=int(g['genesis_time']),
                genesis_validators_root=hex_bytes(g['genesis_validators_root'], 32),
                previous_version=hex_bytes(f['previous_version'], 4),
                current_version=hex_bytes(f['current_version'], 4),
                epoch=int(f['epoch']))


def light_client_header(lc):
    """The header whose state a light-client finality update or bootstrap (beacon API `data`) proves into."""
    if 'finality_branch' in lc:
        return header_of(lc['attested_header']['beacon'])
    if 'current_sync_committee_branch' in lc:
        return header_of(lc['header']['beacon'])
    raise ValueError('neither a light-client finality update nor a bootstrap')


def light_client_nodes(lc):
    """The header of a light-client finality update or bootstrap (beacon API `data`), the STATE_LAYOUTS shape of
    that header's state, and the nodes the branch fixes in it. The shape is the one whose path the branch hashes
    to the header's state_root; raises if there is none."""
    header = light_client_header(lc)
    if 'finality_branch' in lc:
        leaf, gindex, branch = (root_of(header_of(lc['finalized_header']['beacon'])), finalized_root_gindex,
                                lc['finality_branch'])
    else:
        committee = lc['current_sync_committee']
        leaf = sync_committee_root([hex_bytes(k, 48) for k in committee['pubkeys']],
                                   hex_bytes(committee['aggregate_pubkey'], 48))
        gindex, branch = current_sync_committee_gindex, lc['current_sync_committee_branch']
    branch = [hex_bytes(b, 32) for b in branch]
    for layout in STATE_LAYOUTS:
        if gindex(layout).bit_length() - 1 == len(branch):
            nodes = walk(leaf, gindex(layout), branch)
            if nodes[1] == header['state_root']:
                return header, layout, nodes
    raise ValueError(f'the light-client branch ({len(branch)} nodes) does not reach its header\'s state_root '
                     f'in any BeaconState shape here ({", ".join(STATE_LAYOUTS)})')


def field_nodes(layout, roots):
    """Every node of a `layout` state's tree that only field roots `roots` (fields 0, 1, ...) hash into."""
    nodes = {STATE_LAYOUTS[layout](i): r for i, r in enumerate(roots)}
    # A parent's index is below its children's, so a descending pass meets both children first.
    for g in range(max(nodes) & ~1, 1, -2):
        if g in nodes and g + 1 in nodes:
            nodes[g >> 1] = node(nodes[g], nodes[g + 1])
    return nodes


def active(bits, field):
    """Whether active-fields bits (node 3, as a chunk) mark `field` active: bit field % 8 of byte field // 8."""
    return bits[field // 8] >> (field % 8) & 1 == 1


def proof_root(p):
    """The beacon block root checkFork computes from proof `p`, in the contract's order."""
    fork = node(node(chunk(p['previousVersion']), chunk(p['currentVersion'])), node(u64(p['epoch']), ZERO[0]))
    fields_1_to_4 = node(node(p['genesisValidatorsRoot'], u64(p['slot'])), node(fork, p['stateBranch'][0]))
    state = node(node(u64(p['genesisTime']), node(fields_1_to_4, p['stateBranch'][1])), p['activeFields'])
    b = p['blockBranch']
    return node(node(b[1], node(b[0], state)), b[2])


def fork_proof(lc, chain, timestamp):
    """checkFork's BeaconProof for the state of light-client data `lc` (see `light_client_nodes`), given that
    state's fields 0, 1 and 3 (`chain_of`) and the timestamp of an execution block whose EIP-4788 root is that
    header's root. Returns (proof, block root). Raises if any input disagrees with another, and UnprovableState if
    the state is not in the shape checkFork hashes."""
    header, layout, nodes = light_client_nodes(lc)
    if layout != CHECK_FORK_LAYOUT:
        raise UnprovableState(f'the light-client branch proves a {layout} BeaconState, and checkFork hashes a '
                              f'{CHECK_FORK_LAYOUT} one, so no checkFork proof of this state exists')
    latest = dict(header, state_root=ZERO[0])
    fields = [u64(chain['genesis_time']), chain['genesis_validators_root'], u64(header['slot']),
              fork_root(chain['previous_version'], chain['current_version'], chain['epoch']), root_of(latest)]
    known = field_nodes(layout, fields)
    if known[GENESIS_TIME] != nodes[GENESIS_TIME]:
        raise ValueError(f'the genesis time {chain["genesis_time"]} is not the state\'s field 0 (node {GENESIS_TIME})')
    if known[FIELDS_1_TO_4] != nodes[FIELDS_1_TO_4]:
        raise ValueError(f'the genesis validators root, the header\'s slot, the fork and the header do not give the '
                         f'state\'s fields 1 to 4 (node {FIELDS_1_TO_4}): the fork is another state\'s, '
                         'or the state\'s fork changed one of those fields')
    bits = nodes[ACTIVE_FIELDS]
    if not all(active(bits, i) for i in range(4)):
        raise UnprovableState(f'the state\'s active-fields bits ({bits.hex()}) leave one of fields 0 to 3 inactive, '
                              'and checkFork refuses that')
    p = dict(timestamp=timestamp, genesisTime=chain['genesis_time'],
             genesisValidatorsRoot=chain['genesis_validators_root'], slot=header['slot'],
             previousVersion=chain['previous_version'], currentVersion=chain['current_version'],
             epoch=chain['epoch'], stateBranch=[known[LATEST_BLOCK_HEADER], nodes[LATER_FIELDS]], activeFields=bits,
             blockBranch=[header['parent_root'], node(u64(header['slot']), u64(header['proposer_index'])),
                          node(node(header['body_root'], ZERO[0]), ZERO[1])])
    if p['genesisTime'] + p['slot'] * SECONDS_PER_SLOT >= timestamp:
        raise ValueError('the EIP-4788 timestamp must be after the state\'s slot time')
    root = root_of(header)
    if proof_root(p) != root:
        raise AssertionError('internal: the proof does not give the header root')
    return p, root
