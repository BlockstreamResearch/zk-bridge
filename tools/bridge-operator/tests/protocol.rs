//! The encodings the commands print, checked against the values other implementations pin: vectors/protocol.json,
//! the Solidity suite's Liquid testnet fixture, and the expected values of bridge-core/test (bridge.test.js,
//! elements.test.js), repeated here so that the two implementations stay equal.
mod common;

use bridge_operator::abi::word;
use bridge_operator::bridge::{
    batch_ref, burn_proof, burn_script, federation, federation_keys, lift_y, redeem_calldata,
    relay_batch, submit_headers_calldata, Address, Batch, BlockRef, BurnProof, RelayBatch, REDEEM,
    REDEEM_TO, SUBMIT_HEADERS,
};
use bridge_operator::elements::{
    block_signatures, display_hex, merkle_branch, parse_der_signature, txid_from_display, Header,
    Signature, Transaction,
};
use bridge_operator::hash::{keccak256, selector, sha256, sha256d};
use bridge_operator::hex;
use common::*;

fn address(fill: &str) -> Address {
    Address::parse(&format!("0x{}", fill.repeat(20))).unwrap()
}

#[test]
fn burn_scripts_match_the_shared_vectors() {
    let vectors = fixture("vectors/protocol.json");
    let cases = vectors["burn_script"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let script = burn_script(
            case["chain_id"].as_u64().unwrap(),
            &Address::parse(case["escrow"].as_str().unwrap()).unwrap(),
            &Address::parse(case["recipient"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(hex::prefixed(&script), case["script"].as_str().unwrap());
        assert_eq!(script.len(), 72);
    }
    assert_eq!(
        vectors["tags"]["burn"].as_str().unwrap().as_bytes(),
        bridge_operator::bridge::BURN_TAG
    );

    // bridge.test.js: abi.encodePacked(hex"6a46", bytes22("liquid-bridge-poc/burn"), uint64(chainid), escrow,
    // recipient), byte by byte.
    let expected = format!(
        "6a466c69717569642d6272696467652d706f632f6275726e0000000000aa36a7{}{}",
        "12".repeat(20),
        "ab".repeat(20)
    );
    assert_eq!(
        hex::encode(&burn_script(11_155_111, &address("12"), &address("ab"))),
        expected
    );
}

/// `n` as a hex word, as bridge.test.js writes them.
fn w(digits: &str) -> String {
    format!("{digits:0>64}")
}

#[test]
fn redeem_and_relay_calldata_follow_the_abi_head_tail_layout() {
    let burn = BurnProof {
        transaction: vec![0xaa, 0xbb],
        vout: 1,
        branch: vec![[0x22; 32]],
        position: 3,
    };
    let block = BlockRef {
        batch: 2,
        index: 1,
        path: vec![[0x55; 32]],
    };
    let expected = [
        w(&"11".repeat(20)),
        w("60"),
        w("160"), // recipient; offsets of burn (96) and ref (96 + 256)
        w("80"),
        w("1"),
        w("c0"),
        w("3"), // burn: offset of the transaction (128), vout, offset of branch (192), position
        w("2"),
        format!("{:0<64}", "aabb"), // transaction
        w("1"),
        "22".repeat(32), // branch
        w("2"),
        w("1"),
        w("60"), // ref: batch, index, offset of path (96)
        w("1"),
        "55".repeat(32), // path
    ]
    .concat();
    let payee = address("11");
    assert_eq!(
        redeem_calldata(REDEEM, &payee, &burn, &block),
        format!("0x{}{expected}", hex::encode(&selector(REDEEM)))
    );
    // redeemTo has the same layout, with the payee in the first word.
    assert_eq!(
        redeem_calldata(REDEEM_TO, &payee, &burn, &block),
        format!("0x{}{expected}", hex::encode(&selector(REDEEM_TO)))
    );
    assert_ne!(selector(REDEEM), selector(REDEEM_TO));

    let relay = RelayBatch {
        headers: vec![vec![0xcc]],
        sigs: vec![Signature {
            r: [0x33; 32],
            s: [0x44; 32],
        }],
        witness_script: vec![],
        key_y: vec![],
        first_height: 0,
    };
    let expected = [
        w("80"),
        w("100"),
        w("160"),
        w("180"), // offsets: headers (128), sigs (256), witnessScript (352), keyY (384)
        w("1"),
        w("20"),
        w("1"),
        format!("{:0<64}", "cc"), // headers
        w("1"),
        "33".repeat(32),
        "44".repeat(32), // sigs
        w("0"),          // empty witnessScript
        w("0"),          // empty keyY
    ]
    .concat();
    assert_eq!(
        submit_headers_calldata(&relay),
        format!("0x{}{expected}", hex::encode(&selector(SUBMIT_HEADERS)))
    );
}

#[test]
fn federation_reads_the_scripts_the_light_client_accepts() {
    let k = |b: u8| {
        let mut key = [b; 33];
        key[0] = 0x02;
        key
    };
    let mut script = vec![0x52, 0x21];
    script.extend(k(1));
    script.push(0x21);
    script.extend(k(2));
    script.push(0x21);
    script.extend(k(3));
    script.extend([0x53, 0xae]);
    let f = federation(&script).unwrap();
    assert_eq!(f.threshold, 2);
    assert_eq!(f.keys, vec![k(1), k(2), k(3)]);
    assert_eq!(federation_keys(&script).unwrap(), f.keys);

    let mut single = vec![0x21];
    single.extend(k(9));
    single.push(0xac);
    assert_eq!(federation(&single).unwrap().threshold, 1);

    // 3-of-1, a wrong OP_n, a key without its push, and no OP_CHECKMULTISIG.
    let mut three_of_one = vec![0x53, 0x21];
    three_of_one.extend(k(1));
    three_of_one.extend([0x51, 0xae]);
    let mut wrong_n = script.clone();
    wrong_n[script.len() - 2] = 0x52;
    let mut unpushed = script.clone();
    unpushed[1] = 0x20;
    let mut no_multisig = script.clone();
    *no_multisig.last_mut().unwrap() = 0xac;
    for bad in [&three_of_one, &wrong_n, &no_multisig, &vec![]] {
        assert!(
            federation(bad).unwrap_err().contains("multisig"),
            "{}",
            hex::encode(bad)
        );
    }
    assert_eq!(
        federation(&unpushed).unwrap_err(),
        "the witness script has a non-compressed key"
    );
}

#[test]
fn lift_y_recovers_the_generator_and_the_parity() {
    let g = |prefix: &str| -> [u8; 33] { hex::decode_array(&format!("{prefix}{G_X}")).unwrap() };
    assert_eq!(hex::encode(&lift_y(&g("02")).unwrap()), G_Y);
    // P - G_Y for the odd prefix.
    assert_eq!(
        hex::encode(&lift_y(&g("03")).unwrap()),
        "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777"
    );
    assert_eq!(lift_y(&g("04")).unwrap_err(), "not a compressed key");
}

#[test]
fn der_signatures() {
    let sig = made_up_sig();
    let Signature { r, s } = parse_der_signature(&sig).unwrap();
    assert_eq!((r, s), ([0x11; 32], [0x2b; 32]));
    // A 33-byte r with its sign-padding zero.
    let padded = hex::decode(&format!(
        "3045022100{}0220{}01",
        "ff".repeat(32),
        "11".repeat(32)
    ))
    .unwrap();
    assert_eq!(parse_der_signature(&padded).unwrap().r, [0xff; 32]);
    assert!(parse_der_signature(&sig[..20]).unwrap_err().contains("DER"));
    let mut trailing = sig.clone();
    trailing.insert(sig.len() - 1, 0);
    assert!(parse_der_signature(&trailing).unwrap_err().contains("DER"));
}

#[test]
fn a_dynafed_header_gives_its_hash_form_height_and_signatures() {
    let full = signed_header([0x11; 32], [0x22; 32], 2_664_802, &made_up_sig());
    let h = Header::parse(&full).unwrap();
    assert_eq!(h.hash_form.len(), 149);
    assert_eq!(h.hash_form[..], full[..149]);
    assert_eq!(h.hash, sha256d(&full[..149]));
    assert_eq!(h.height, 2_664_802);
    assert_eq!(h.signblockscript, p2wsh(&witness_script()));
    let (script, sigs) = block_signatures(&h).unwrap();
    assert_eq!(script, witness_script());
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].r, [0x11; 32]);

    let unsigned = Header::parse(&full[..149]).unwrap();
    assert!(block_signatures(&unsigned)
        .unwrap_err()
        .contains("no signblock witness"));
    let mut trailing = full.clone();
    trailing.push(0);
    assert!(Header::parse(&trailing).unwrap_err().contains("trailing"));
    let mut legacy = full.clone();
    legacy[3] = 0x20; // clear the DynaFed bit
    assert!(Header::parse(&legacy)
        .unwrap_err()
        .contains("not a DynaFed"));
    assert!(Header::parse(&full[..100])
        .unwrap_err()
        .contains("truncated"));
}

#[test]
fn a_real_liquid_testnet_epoch_start_header() {
    let signed = real_signed();
    assert_eq!(signed.len() / 2, 323);
    let h = Header::parse(&hex::decode(&signed).unwrap()).unwrap();
    assert_eq!(hex::encode(&h.hash_form), REAL_HASH_FORM);
    assert_eq!(
        display_hex(&h.hash),
        "1a195d11b63038c91100a09efdb1489ae16e6f6f64cdc20a227015bc4ba77eb7",
        "the block id Blockstream displays"
    );
    assert_eq!(h.height, 2_664_000);
    let (script, sigs) = block_signatures(&h).unwrap();
    assert_eq!(hex::encode(&script), REAL_SCRIPT);
    assert_eq!(hex::encode(&sigs[0].r), REAL_R);
    assert_eq!(hex::encode(&sigs[0].s), REAL_S);

    // As a relay batch: no witness script unless the light client holds another signing script.
    let own = keccak256(&h.signblockscript);
    let same = relay_batch(&[signed.clone()], &own).unwrap();
    assert_eq!(hex::encode(&same.headers[0]), REAL_HASH_FORM);
    assert!(same.witness_script.is_empty() && same.key_y.is_empty());
    let changed = relay_batch(&[signed], &[0x11; 32]).unwrap();
    assert_eq!(hex::encode(&changed.witness_script), REAL_SCRIPT);
    let key_y: Vec<String> = changed.key_y.iter().map(|y| hex::prefixed(y)).collect();
    // The Solidity fixture's keyY for the same script.
    assert_eq!(key_y, vec![REAL_KEY_Y.to_owned()]);
    let fixture = fixture("contracts/solidity/test/fixtures/liquid-testnet-headers.json");
    assert_eq!(fixture["keyY"][0], REAL_KEY_Y);
    assert_eq!(
        hex::prefixed(&changed.witness_script),
        fixture["witnessScript"].as_str().unwrap()
    );
}

#[test]
fn the_solidity_fixture_chain_and_burn_proof() {
    let f = fixture("contracts/solidity/test/fixtures/liquid-testnet-headers.json");
    let hashes =
        |v: &serde_json::Value| -> [u8; 32] { hex::decode_array(v.as_str().unwrap()).unwrap() };

    // Each batch's hash forms link to the checkpoint and to each other, and end at the batch's tip.
    let mut by_height = std::collections::HashMap::new();
    for batch in f["batches"].as_array().unwrap() {
        let first = batch["firstHeight"].as_u64().unwrap();
        let headers: Vec<Header> = batch["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| Header::parse(&hex::decode(h.as_str().unwrap()).unwrap()).unwrap())
            .collect();
        for (i, h) in headers.iter().enumerate() {
            assert_eq!(u64::from(h.height), first + i as u64);
            if i > 0 {
                assert_eq!(h.prev, headers[i - 1].hash);
            }
        }
        assert_eq!(headers.last().unwrap().hash, hashes(&batch["tipHash"]));
        assert_eq!(
            display_hex(&headers.last().unwrap().hash),
            batch["tipId"].as_str().unwrap()
        );
        for h in headers {
            by_height.insert(u64::from(h.height), h);
        }
    }
    assert_eq!(by_height[&2_664_000].prev, hashes(&f["checkpointHash"]));

    // The fixture's transaction: its txid, and the burn proof BridgeEscrow's tests take for it.
    let tx = &f["tx"];
    let parsed =
        Transaction::parse(&hex::decode(tx["txidForm"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(parsed.txid, hashes(&tx["txid"]));
    assert_eq!(display_hex(&parsed.txid), tx["id"].as_str().unwrap());
    let height = tx["height"].as_u64().unwrap();
    let branch: Vec<[u8; 32]> = tx["branch"]
        .as_array()
        .unwrap()
        .iter()
        .map(hashes)
        .collect();
    let position = tx["position"].as_u64().unwrap() as usize;
    // A block of two transactions: the branch is the other one's txid.
    let mut txids = vec![display_hex(&branch[0])];
    txids.insert(position, tx["id"].as_str().unwrap().to_owned());
    let proven = burn_proof(
        tx["id"].as_str().unwrap(),
        tx["txidForm"].as_str().unwrap(),
        0,
        &txids,
        &hex::encode(&by_height[&height].hash_form),
    )
    .unwrap();
    assert_eq!(proven.height, height);
    assert_eq!(proven.burn.position as usize, position);
    assert_eq!(proven.burn.branch, branch);
    assert_eq!(proven.burn.transaction, parsed.txid_form);
}

#[test]
fn transactions_are_read_in_full() {
    let f = fixture("contracts/solidity/test/fixtures/liquid-testnet-headers.json");
    let form = hex::decode(f["tx"]["txidForm"].as_str().unwrap()).unwrap();
    assert_eq!(form[4], 0, "flags byte cleared in the txid form");
    let mut trailing = form.clone();
    trailing.push(0);
    assert!(Transaction::parse(&trailing)
        .unwrap_err()
        .contains("trailing"));
    assert!(Transaction::parse(&form[..form.len() - 1])
        .unwrap_err()
        .contains("truncated"));
}

#[test]
fn merkle_branches_including_the_duplicated_last_leaf() {
    let leaves: Vec<[u8; 32]> = (1..=3u8).map(|i| sha256(&[i])).collect();
    let n01 = sha256d(&[leaves[0], leaves[1]].concat());
    let n22 = sha256d(&[leaves[2], leaves[2]].concat());
    let root = sha256d(&[n01, n22].concat());
    for i in 0..3 {
        assert_eq!(merkle_branch(&leaves, i).unwrap().0, root);
    }
    assert_eq!(merkle_branch(&leaves, 1).unwrap().1, vec![leaves[0], n22]);
    assert_eq!(merkle_branch(&leaves, 2).unwrap().1, vec![leaves[2], n01]);
    assert!(merkle_branch(&leaves[..1], 0).unwrap().1.is_empty());
    assert!(merkle_branch(&leaves, 3).is_err());
}

#[test]
fn burn_proof_batch_reference_and_relay_batch_from_synthetic_signed_headers() {
    let script = burn_script(11_155_111, &address("12"), &address("ab"));
    let tx = burn_tx(&script);
    let parsed = Transaction::parse(&tx).unwrap();
    let other = sha256(&[7]);
    let root = sha256d(&[other, parsed.txid].concat());
    let h0 = signed_header([9; 32], root, 5000, &made_up_sig());
    let h1 = signed_header(
        Header::parse(&h0).unwrap().hash,
        [1; 32],
        5001,
        &made_up_sig(),
    );

    // Burn proof: the transaction's position and branch in its block.
    let txid = display_hex(&parsed.txid);
    let txids = vec![display_hex(&other), txid.clone()];
    let p = burn_proof(&txid, &hex::encode(&tx), 0, &txids, &hex::encode(&h0)).unwrap();
    assert_eq!(p.burn.position, 1);
    assert_eq!(p.burn.branch, vec![other]);
    assert_eq!(p.burn.transaction, tx);
    assert_eq!(p.height, 5000);
    let swapped = vec![txid.clone(), display_hex(&other)];
    assert!(
        burn_proof(&txid, &hex::encode(&tx), 0, &swapped, &hex::encode(&h0))
            .unwrap_err()
            .contains("Merkle root")
    );
    assert!(burn_proof(
        &"00".repeat(32),
        &hex::encode(&tx),
        0,
        &[],
        &hex::encode(&h0)
    )
    .unwrap_err()
    .contains("do not match the txid"));
    assert!(burn_proof(
        &txid,
        &hex::encode(&tx),
        0,
        &[display_hex(&other)],
        &hex::encode(&h0)
    )
    .unwrap_err()
    .contains("not in that block"));

    // Batch reference: LiquidLightClient's keccak tree over three Merkle roots, padded to four leaves.
    let roots = [root, [1; 32], [2; 32]];
    let leaves = [
        keccak256(&roots[0]),
        keccak256(&roots[1]),
        keccak256(&roots[2]),
        [0; 32],
    ];
    let left = keccak256(&[leaves[0], leaves[1]].concat());
    let right = keccak256(&[leaves[2], leaves[3]].concat());
    let batch = Batch {
        index: 4,
        first_height: 5000,
        count: 3,
        root: keccak256(&[left, right].concat()),
    };
    let r = batch_ref(&batch, &roots, 5001).unwrap();
    assert_eq!((r.batch, r.index), (4, 1));
    assert_eq!(r.path, vec![leaves[0], right]);
    let wrong = Batch {
        root: [0; 32],
        ..batch.clone()
    };
    assert!(batch_ref(&wrong, &roots, 5001)
        .unwrap_err()
        .contains("differs"));
    assert!(batch_ref(&batch, &roots, 5003)
        .unwrap_err()
        .contains("outside"));
    assert!(batch_ref(&batch, &roots[..2], 5001)
        .unwrap_err()
        .contains("one Merkle root"));

    // batchAt's return value.
    let data = [word(5000), word(3), batch.root].concat();
    assert_eq!(Batch::decode(&data, 4).unwrap(), batch);
    assert!(Batch::decode(&data[..95], 4).is_err());

    // Relay batch: hash forms, the tip's signatures, and keys only when the signing script changes.
    let hexes = [hex::encode(&h0), hex::encode(&h1)];
    let spk = p2wsh(&witness_script());
    let same = relay_batch(&hexes, &keccak256(&spk)).unwrap();
    assert_eq!(same.headers.len(), 2);
    assert_eq!(same.headers[0].len(), 149, "hash form without the witness");
    assert_eq!(same.sigs.len(), 1);
    assert!(same.witness_script.is_empty() && same.key_y.is_empty());
    assert_eq!(same.first_height, 5000);
    let changed = relay_batch(&hexes, &[0; 32]).unwrap();
    assert_eq!(changed.witness_script, witness_script());
    assert_eq!(hex::encode(&changed.key_y[0]), G_Y);
    let broken = signed_header([0; 32], [1; 32], 5001, &made_up_sig());
    assert!(
        relay_batch(&[hexes[0].clone(), hex::encode(&broken)], &[0; 32])
            .unwrap_err()
            .contains("not the child")
    );
    assert!(relay_batch(&[], &[0; 32]).is_err());
}

#[test]
fn display_order_is_reversed() {
    let display = format!("{}01", "00".repeat(31));
    let internal = txid_from_display(&display).unwrap();
    assert_eq!(internal[0], 1);
    assert_eq!(display_hex(&internal), display);
    assert!(txid_from_display("00").is_err());
    assert!(
        txid_from_display(&format!("0x{}", "00".repeat(31))).is_err(),
        "64 characters, but 0x-prefixed"
    );
}
