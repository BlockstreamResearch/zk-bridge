//! The claim leaf over stock Elements jets: claims are sound without any proof beyond the accumulator committed in
//! the state, in any order and each exactly once. The update leaf is not run here; it stands beside the claim leaf
//! by CMR.

mod common;

use common::{manifest_params, published_manifests};
use zk_bridge::claim::*;
use zk_bridge::crypto::sha;

use simplicity::elements::{
    confidential::{Asset, Value},
    hashes::Hash,
    secp256k1_zkp::ZERO_TWEAK,
    OutPoint, Script, Txid,
};
use simplicity::jet::elements::ElementsUtxo;

fn update_cmr() -> [u8; 32] {
    sha(b"test-only stand-in for the update leaf CMR")
}

/// Deposit scripts of the fixtures: an ordinary segwit wallet (P2WPKH), a wrapped-segwit wallet (P2SH)
/// and a Taproot key, the generator's x. Each deposit commits SHA256 of its script.
fn scripts() -> Vec<Script> {
    let g =
        hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    vec![
        Script::from([&[0x00, 0x14][..], &[0x11; 20]].concat()),
        Script::from([&[0xa9, 0x14][..], &[0x22; 20], &[0x87]].concat()),
        Script::from([&[0x51, 0x20][..], &g].concat()),
    ]
}

fn setup() -> (Bridge, DepositTree, Vec<Script>) {
    let params = test_params();
    check_params(&params).unwrap();
    let bridge = Bridge::new(params.clone(), update_cmr()).unwrap();
    let scripts = scripts();
    let mut tree = DepositTree::new(params.deposit_domain);
    for (k, s) in scripts.iter().enumerate() {
        assert!(
            is_standard_recipient(s.as_bytes()),
            "fixture script {k} is a BridgeDeposits recipient"
        );
        tree.push(100_000 + 1_000 * k as u64, sha(s.as_bytes()));
    }
    (bridge, tree, scripts)
}

fn start() -> OutPoint {
    OutPoint::new(Txid::from_byte_array([12; 32]), 1)
}

fn at(tree: &DepositTree, claimed: &ClaimedTree) -> State {
    State {
        lc: [1; 32],
        acc: tree.accumulator(),
        claimed_root: claimed.root(),
    }
}

/// A published instance's claim leaf: the source text built from its manifest's parameters hashes to the
/// manifest's `claim_leaf.source_sha256` and compiles to its `claim_leaf.cmr`, the leaf its state tree commits.
#[test]
fn published_claim_leaves_are_reproduced() {
    let manifests = published_manifests();
    if manifests.is_empty() {
        println!("no published instance record under instances/: nothing to reproduce");
    }
    for (record, m) in manifests {
        let p = manifest_params(&m);
        check_params(&p).unwrap();
        let leaf = &m["claim_leaf"];
        assert_eq!(
            hex::encode(sha(source(&p).as_bytes())),
            leaf["source_sha256"].as_str().unwrap(),
            "{record}: source text"
        );
        let cmr = compile(&p).unwrap().commit().cmr();
        assert_eq!(
            hex::encode(cmr.as_ref()),
            leaf["cmr"].as_str().unwrap(),
            "{record}: CMR"
        );
    }
}

#[test]
fn deposit_tree_branches_stay_valid_as_it_grows() {
    let mut tree = DepositTree::new(test_params().deposit_domain);
    assert_eq!(tree.accumulator(), accumulator(tree.root(), 0));
    for k in 0..9u64 {
        tree.push(100_000 + k, [k as u8 + 1; 32]);
        let root = tree.root();
        for i in 0..tree.count() {
            assert_eq!(root_from_branch(tree.leaf(i), i, &tree.branch(i)), root);
        }
        if tree.count() > 1 {
            assert_ne!(root_from_branch(tree.leaf(0), 1, &tree.branch(0)), root);
            assert_ne!(root_from_branch(tree.leaf(1), 1, &tree.branch(0)), root);
        }
    }
}

/// The claimed root is a function of the set alone; every slot opens under it to exactly its value; and the
/// closed form of a complete tree agrees with the tree.
#[test]
fn claimed_tree_roots_bind_the_set() {
    let empty = ClaimedTree::new();
    assert_eq!(empty.root(), empty_roots()[TREE_DEPTH]);
    assert_eq!(empty.root(), DepositTree::new([0; 32]).root());
    assert_eq!(complete_root(0), empty.root());

    let by = |order: &[u64]| order.iter().fold(ClaimedTree::new(), |t, &k| t.with(k));
    let a = by(&[5, 0, 3]);
    assert_eq!(a, by(&[3, 5, 0]));
    assert_eq!(a.root(), by(&[0, 3, 5]).root());
    assert_eq!(a.with(3), a, "setting a set slot again changes nothing");
    assert_ne!(a.with(4).root(), a.root());
    assert_ne!(by(&[1]).root(), by(&[2]).root());
    assert_eq!(a.len(), 3);

    let far = (1u64 << TREE_DEPTH) - 1;
    let b = a.with(far);
    for t in [&empty, &a, &b] {
        let root = t.root();
        for i in (0..9).chain([far - 1, far]) {
            let (value, other) = if t.contains(i) {
                (claimed_leaf(), [0; 32])
            } else {
                ([0; 32], claimed_leaf())
            };
            assert_eq!(root_from_branch(value, i, &t.branch(i)), root, "slot {i}");
            assert_ne!(
                root_from_branch(other, i, &t.branch(i)),
                root,
                "slot {i} flipped"
            );
        }
    }

    let mut prefix = ClaimedTree::new();
    for n in 0..40 {
        assert_eq!(complete_root(n), prefix.root(), "complete_root({n})");
        prefix = prefix.with(n);
    }
    assert_ne!(complete_root(1 << TREE_DEPTH), complete_root(far));
}

/// Claims taken out of deposit order, the lowest index last, each spend the previous claim's successor: one token
/// chain, one deposit per step, ending at the complete root.
#[test]
fn claims_in_any_order_form_one_token_chain() {
    let (bridge, tree, scripts) = setup();
    let mut claimed = ClaimedTree::new();
    let mut state = at(&tree, &claimed);
    let (mut phase, mut prev, mut previous_output) = (0, start(), None);
    let mut reports = vec![];
    for index in [2u64, 1, 0] {
        let script = scripts[index as usize].clone();
        let s = bridge.claim(&state, &claimed, index, phase, prev, &tree, 1_000, script);
        if let Some(out) = previous_output.take() {
            assert_eq!(
                ElementsUtxo::from(s.spent[0].clone()),
                ElementsUtxo::from(out)
            );
        }
        assert_eq!(s.tx.output[0].script_pubkey, bridge.state_script(&s.new));
        let report = bridge.run(&s, true).unwrap();
        assert!(
            report.budget_valid_without_padding,
            "the claim's cost fits the budget of its own witness stack: {report:?}"
        );
        reports.push(report);
        previous_output = Some(s.tx.output[0].clone());
        prev = OutPoint::new(s.tx.txid(), 0);
        claimed = claimed.with(index);
        assert_eq!(s.new.claimed_root, claimed.root());
        state = s.new;
        phase = 1 - phase;
    }
    assert_eq!(claimed.len(), 3);
    assert_eq!(state.claimed_root, complete_root(tree.count()));
    assert_eq!(state.acc, tree.accumulator());
    println!("claim chain {}", serde_json::to_string(&reports).unwrap());
}

/// A set slot cannot be claimed again: not with its current branch, which opens it as set, and not with the branch
/// it had before it was set, which no longer opens to the state's root.
#[test]
fn claims_are_exact_once() {
    let (bridge, tree, scripts) = setup();
    let mut claimed = ClaimedTree::new();
    let mut state = at(&tree, &claimed);
    for index in [1u64, 0, 2] {
        let script = scripts[index as usize].clone();
        let s = bridge.claim(
            &state,
            &claimed,
            index,
            0,
            start(),
            &tree,
            1_000,
            script.clone(),
        );
        bridge.run(&s, true).unwrap();
        let before = claimed.clone();
        claimed = claimed.with(index);
        state = s.new;

        let again = bridge.claim(&state, &claimed, index, 0, start(), &tree, 1_000, script);
        assert_eq!(
            again.new, state,
            "setting a set slot leaves the state as it was"
        );
        assert!(
            bridge.run(&again, false).is_err(),
            "deposit {index} claimed twice"
        );
        let mut stale = again.clone();
        stale
            .witness
            .insert("CLAIMED_PATH", path_value(&before.branch(index)));
        assert!(
            bridge.run(&stale, false).is_err(),
            "deposit {index} claimed twice with the branch from before its claim"
        );
    }
    assert_eq!(state.claimed_root, complete_root(3));
}

/// Two deposits with the same units and recipient are two deposits: each leaf commits its own index, and each index
/// has its own claimed slot.
#[test]
fn duplicate_deposits_are_distinct_by_index() {
    let (bridge, _, scripts) = setup();
    let recipient = sha(scripts[0].as_bytes());
    let mut tree = DepositTree::new(bridge.params.deposit_domain);
    tree.push(100_000, recipient);
    tree.push(100_000, recipient);
    assert_ne!(tree.leaf(0), tree.leaf(1));

    let mut claimed = ClaimedTree::new();
    let mut state = at(&tree, &claimed);
    for index in [1u64, 0] {
        let script = scripts[0].clone();
        let s = bridge.claim(&state, &claimed, index, 0, start(), &tree, 1_000, script);
        let mut swapped = s.clone();
        swapped
            .witness
            .insert("PATH", path_value(&tree.branch(1 - index)));
        assert!(
            bridge.run(&swapped, false).is_err(),
            "deposit {index} opened with its twin's branch"
        );
        bridge.run(&s, true).unwrap();
        // Recovery from public data: both twins match the mint, and of the unclaimed ones only the deposit
        // claimed gives output 0's successor, so the claimed set is rebuilt without decoding the witness.
        let successor_of = |k: u64| {
            let new = State {
                claimed_root: claimed.with(k).root(),
                ..state
            };
            bridge.state_script(&new)
        };
        let recovered: Vec<u64> = (0..tree.count())
            .filter(|&k| !claimed.contains(k))
            .filter(|&k| successor_of(k) == s.tx.output[0].script_pubkey)
            .collect();
        assert_eq!(recovered, vec![index]);
        claimed = claimed.with(index);
        state = s.new;
    }
    for index in [0u64, 1] {
        let script = scripts[0].clone();
        let again = bridge.claim(&state, &claimed, index, 0, start(), &tree, 1_000, script);
        assert!(
            bridge.run(&again, false).is_err(),
            "duplicate deposit {index} claimed twice"
        );
    }
    assert_eq!(state.claimed_root, complete_root(2));
}

#[test]
fn claim_rejects_mutations() {
    let (bridge, tree, scripts) = setup();
    claim_mutations(&bridge, &tree, &|i| scripts[i].clone());
}

/// The claim leaf pays every deposit to exactly its committed script, whatever the script's type; P2TR
/// of the committed hash is refused.
#[test]
fn claim_pays_the_committed_script() {
    let (bridge, tree, scripts) = setup();
    let mut claimed = ClaimedTree::new();
    let mut state = at(&tree, &claimed);
    for (i, script) in scripts.iter().enumerate() {
        let index = i as u64;
        let (_, recipient) = tree.deposits[i];
        let wrong = p2tr(recipient);
        let wrong = bridge.claim(&state, &claimed, index, 0, start(), &tree, 1_000, wrong);
        assert!(
            bridge.run(&wrong, false).is_err(),
            "P2TR(recipient) is not the committed script of deposit {i}"
        );
        let s = bridge.claim(
            &state,
            &claimed,
            index,
            0,
            start(),
            &tree,
            1_000,
            script.clone(),
        );
        bridge.run(&s, true).unwrap();
        assert_eq!(s.tx.output[1].script_pubkey, *script);
        claimed = claimed.with(index);
        state = s.new;
    }
    assert_eq!(state.claimed_root, complete_root(3));
    for s in ["", "6a20", "5220"] {
        assert!(
            !is_standard_recipient(&hex::decode(s).unwrap()),
            "{s:?} is not a recipient script"
        );
    }
    assert!(
        !is_standard_recipient(&[&[0x51, 0x20][..], &[0xff; 32]].concat()),
        "a P2TR key above the field prime"
    );
}

/// The fee output must be in the fee asset (L-BTC).
#[test]
fn claim_pins_the_fee_asset() {
    let (bridge, tree, scripts) = setup();
    let claimed = ClaimedTree::new();
    let state = at(&tree, &claimed);
    let claim = bridge.claim(
        &state,
        &claimed,
        0,
        0,
        start(),
        &tree,
        1_000,
        scripts[0].clone(),
    );
    bridge.run(&claim, true).unwrap();
    let mut fee_in_bridge_asset = claim.clone();
    fee_in_bridge_asset.tx.output[2].asset = Asset::Explicit(bridge.params.asset());
    // Amount proofs are not checked here: the shape is what the leaf sees.
    assert!(
        bridge.run(&fee_in_bridge_asset, false).is_err(),
        "the claim leaf requires the fee asset"
    );
}

/// A reissuance that also carries inflation keys is not visible to any Simplicity program: for a
/// reissuance, the Elements environment reports the token amount as explicit 0
/// (simplicity-sys elements/elementsJets.c `issuanceTokenAmt`; env.c copies inflation keys only for
/// a new issuance), because Elements consensus already rejects that shape ("Only initial issuance can
/// have reissuance tokens", Elements src/confidential_validation.cpp VerifyAmounts). The claim leaf
/// therefore accepts it and relies on consensus. This test pins that boundary: if the environment ever
/// reported reissuance inflation keys, it would fail and the leaf's own token-amount check would be
/// doing work again.
#[test]
fn reissuance_inflation_keys_are_left_to_consensus() {
    let (bridge, tree, scripts) = setup();
    let claimed = ClaimedTree::new();
    let state = at(&tree, &claimed);
    let mut s = bridge.claim(
        &state,
        &claimed,
        1,
        0,
        start(),
        &tree,
        1_000,
        scripts[1].clone(),
    );
    s.tx.input[0].asset_issuance.inflation_keys = Value::Explicit(1);
    assert!(
        bridge.run(&s, false).is_ok(),
        "the leaf cannot observe inflation keys on a reissuance"
    );
}

/// Mutations of an honest claim of deposit 1, after deposit 2 and before deposit 0, that `bridge`'s claim leaf
/// must reject; `script_of(i)` is the output script deposit i is paid to.
fn claim_mutations(bridge: &Bridge, tree: &DepositTree, script_of: &dyn Fn(usize) -> Script) {
    let p = bridge.params.clone();
    let claimed = ClaimedTree::new().with(2);
    let state = at(tree, &claimed);
    let base = bridge.claim(&state, &claimed, 1, 0, start(), tree, 1_000, script_of(1));
    bridge.run(&base, true).unwrap();
    bridge.run(&base, false).unwrap();
    let (units, _) = tree.deposits[1];
    let (units2, recipient2) = tree.deposits[2];
    let mut one = DepositTree::new(p.deposit_domain);
    one.push(tree.deposits[0].0, tree.deposits[0].1);
    let successor = |set: &[u64]| {
        let t = set.iter().fold(ClaimedTree::new(), |t, &k| t.with(k));
        bridge.state_script(&State {
            claimed_root: t.root(),
            ..state
        })
    };
    assert_eq!(base.tx.output[0].script_pubkey, successor(&[1, 2]));
    for case in 0..32 {
        let mut s = base.clone();
        match case {
            0 => s.tx.output[1].value = Value::Explicit(units + 1),
            1 => {
                s.tx.input[0].asset_issuance.amount = Value::Explicit(units + 1);
                s.tx.output[1].value = Value::Explicit(units + 1);
            }
            2 => s.tx.output[1].script_pubkey = p2tr([7; 32]),
            3 => {
                s.witness.insert("RECIPIENT", u256([7; 32]));
                s.tx.output[1].script_pubkey = p2tr([7; 32]);
            }
            // Deposit 1's units and recipient at another index.
            4 => {
                s.witness.insert("INDEX", u64_value(2));
            }
            5 => {
                s.witness.insert("INDEX", u64_value(0));
            }
            6 => {
                // Claim deposit 2 again: a consistent claim of it, whose successor leaves the claimed set as
                // it is, against a state in which its slot is set.
                s.witness.insert("INDEX", u64_value(2));
                s.witness.insert("RECIPIENT", u256(recipient2));
                s.witness.insert("PATH", path_value(&tree.branch(2)));
                s.witness
                    .insert("CLAIMED_PATH", path_value(&claimed.branch(2)));
                s.tx.input[0].asset_issuance.amount = Value::Explicit(units2);
                s.tx.output[1].value = Value::Explicit(units2);
                s.tx.output[1].script_pubkey = script_of(2);
                s.tx.output[0].script_pubkey = successor(&[2]);
            }
            7 => {
                let mut branch = tree.branch(1);
                branch[0][0] ^= 1;
                s.witness.insert("PATH", path_value(&branch));
            }
            8 => {
                s.witness.insert("COUNT", u64_value(5));
            }
            9 => {
                // Claim past the end: the state's accumulator opens to a one-deposit tree.
                let short = State {
                    acc: one.accumulator(),
                    ..state
                };
                s = bridge.claim(&short, &claimed, 1, 0, start(), tree, 1_000, script_of(1));
                s.witness.insert("TREE_ROOT", u256(one.root()));
                s.witness.insert("COUNT", u64_value(1));
            }
            10 => {
                s.witness.insert("TREE_ROOT", u256(one.root()));
            }
            // The successor does not set the slot.
            11 => s.tx.output[0].script_pubkey = bridge.state_script(&state),
            // The successor sets another slot, the slot and another, or the slot but clears another.
            12 => s.tx.output[0].script_pubkey = successor(&[0, 2]),
            13 => s.tx.output[0].script_pubkey = successor(&[0, 1, 2]),
            14 => s.tx.output[0].script_pubkey = successor(&[1]),
            15 => {
                let mut branch = claimed.branch(1);
                branch[0][0] ^= 1;
                s.witness.insert("CLAIMED_PATH", path_value(&branch));
            }
            16 => {
                // Level 1 is the one sibling of slot 1 above a set slot.
                let mut branch = claimed.branch(1);
                branch[1][31] ^= 1;
                s.witness.insert("CLAIMED_PATH", path_value(&branch));
            }
            17 => {
                // A claimed root and branch that agree, of nothing claimed, under the real state's output.
                s.witness
                    .insert("CLAIMED_ROOT", u256(ClaimedTree::new().root()));
                s.witness
                    .insert("CLAIMED_PATH", path_value(&ClaimedTree::new().branch(1)));
                s.tx.output[0].script_pubkey = successor(&[1]);
            }
            18 => s.tx.output[0].asset = p.token_asset(0),
            19 => s.tx.output[0].value = Value::Explicit(1),
            20 => s.tx.output.push(s.tx.output[2].clone()),
            21 => s.tx.input[1].asset_issuance = s.tx.input[0].asset_issuance,
            22 => s.tx.output[2].script_pubkey = Script::from(vec![0x51]),
            23 => s.tx.input[0].asset_issuance.asset_entropy[0] ^= 1,
            24 => s.tx.output[1].asset = Asset::Explicit(p.fee_asset),
            25 => {
                s.witness.insert("SIBLING", u256([3; 32]));
            }
            26 => {
                s.tx.input.push(s.tx.input[1].clone());
                s.tx.input[2].previous_output = fee_input(17);
                s.spent.push(s.spent[1].clone());
            }
            27 => {
                // A successor that also changes the light-client commitment.
                let other = State {
                    lc: [9; 32],
                    ..base.new
                };
                s.tx.output[0].script_pubkey = bridge.state_script(&other);
            }
            // A new issuance on input 0 (zero blinding nonce) instead of a reissuance: it could create
            // tokens, and `current_reissuance_entropy` is None for it, so the leaf rejects it. (A
            // reissuance carrying inflation keys is consensus-invalid instead; see the test above.)
            28 => {
                s.tx.input[0].asset_issuance.asset_blinding_nonce = ZERO_TWEAK;
                s.tx.input[0].asset_issuance.inflation_keys = Value::Explicit(1);
            }
            // The spent output holds the token unblinded: the state's only authentication is the token
            // commitment under public factor A or B, since NUMS rules out a key path.
            29 => s.spent[0].asset = Asset::Explicit(p.token()),
            30 => s.tx.input[0].asset_issuance = Default::default(),
            // An index that agrees with deposit 1's in its low 32 bits.
            31 => {
                s.witness.insert("INDEX", u64_value(1 + (1 << TREE_DEPTH)));
            }
            _ => unreachable!(),
        }
        assert!(
            bridge.run(&s, false).is_err(),
            "claim leaf accepted mutation {case}"
        );
    }
}

#[test]
fn leaves_and_state_are_bound_by_the_control_block() {
    let (bridge, tree, scripts) = setup();
    let claimed = ClaimedTree::new();
    let state = at(&tree, &claimed);
    // The update leaf's control block does not commit the claim leaf.
    let mut s = bridge.claim(
        &state,
        &claimed,
        0,
        0,
        start(),
        &tree,
        1_000,
        scripts[0].clone(),
    );
    s.control = bridge.control(&state, &bridge.update_cmr);
    assert!(bridge
        .run(&s, false)
        .unwrap_err()
        .contains("control block commitment"));
    // The state output belongs to another state: the witness state no longer matches its path.
    let mut s = bridge.claim(
        &state,
        &claimed,
        0,
        0,
        start(),
        &tree,
        1_000,
        scripts[0].clone(),
    );
    let other = State {
        lc: [8; 32],
        ..state
    };
    s.spent[0].script_pubkey = bridge.state_script(&other);
    s.control = bridge.control(&other, bridge.claim_cmr.as_ref());
    assert!(bridge.run(&s, false).is_err());
}

#[test]
fn bootstrap_issues_the_token_into_the_first_state() {
    let (bridge, tree, scripts) = setup();
    let claimed = ClaimedTree::new();
    let initial = at(&tree, &claimed);
    // test_params derives the entropy from this outpoint with a zero contract hash.
    let funding = OutPoint::new(Txid::from_byte_array([12; 32]), 0);
    let (boot, spent) = bridge.bootstrap(funding, 50_000, &initial);
    boot.verify_tx_amt_proofs(
        &simplicity::elements::secp256k1_zkp::Secp256k1::new(),
        &spent,
    )
    .unwrap();
    let entropy = simplicity::elements::AssetId::generate_asset_entropy(
        funding,
        simplicity::elements::issuance::ContractHash::from_byte_array(
            boot.input[0].asset_issuance.asset_entropy,
        ),
    );
    assert_eq!(entropy.to_byte_array(), bridge.params.entropy);
    assert_eq!(boot.output[0].script_pubkey, bridge.state_script(&initial));
    let claim = bridge.claim(
        &initial,
        &claimed,
        0,
        0,
        OutPoint::new(boot.txid(), 0),
        &tree,
        1_000,
        scripts[0].clone(),
    );
    assert_eq!(
        ElementsUtxo::from(claim.spent[0].clone()),
        ElementsUtxo::from(boot.output[0].clone())
    );
    bridge.run(&claim, true).unwrap();
}
