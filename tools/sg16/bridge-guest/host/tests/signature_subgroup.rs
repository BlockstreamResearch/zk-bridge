//! The signature's subgroup check is its decoder's. A point on the G2 curve outside the r-order subgroup decodes
//! unchecked but not checked, so `Signature::verify` refuses it. Helios also ran a helper, removed in
//! patches/helios-consensus-core, that multiplied by `Scalar::from_raw(r)`; that scalar is zero, so the helper
//! accepted every point, this one included.

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G2Affine, G2Projective, Scalar,
};
use helios_consensus_core::types::bls::Signature;
use ssz::Decode;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const MSG: &[u8] = b"liquid-bridge-poc signature subgroup test";

/// The compressed point with x = k (k = 1, 2, ...) of the first such point on the G2 curve outside the subgroup.
fn non_subgroup_point() -> [u8; 96] {
    for k in 1..=255u8 {
        let mut bytes = [0u8; 96];
        bytes[0] = 0x80; // compressed; x.c1 = 0
        bytes[95] = k; // x.c0 = k
        let on_curve = bool::from(G2Affine::from_compressed_unchecked(&bytes).is_some());
        if on_curve && bool::from(G2Affine::from_compressed(&bytes).is_none()) {
            return bytes;
        }
    }
    panic!("no small x gives a curve point outside the subgroup");
}

fn signature(bytes: &[u8; 96]) -> Signature {
    Signature::from_ssz_bytes(bytes).unwrap()
}

/// A secret key, its public key and its signature of MSG.
fn signed() -> (G1Affine, [u8; 96]) {
    let sk = Scalar::from(0x5eed_u64);
    let h = <G2Projective as HashToCurve<ExpandMsgXmd<sha2_09::Sha256>>>::hash_to_curve(MSG, DST);
    let pk = G1Affine::from(G1Affine::generator() * sk);
    (pk, G2Affine::from(h * sk).to_compressed())
}

#[test]
fn a_valid_signature_verifies() {
    let (pk, sig) = signed();
    assert!(signature(&sig).verify(MSG, &pk));
    assert!(!signature(&sig).verify(b"another message", &pk));
}

#[test]
fn a_point_outside_the_subgroup_is_refused() {
    let bytes = non_subgroup_point();
    let point = G2Affine::from_compressed_unchecked(&bytes).unwrap();
    assert!(!bool::from(point.is_torsion_free()));
    let (pk, _) = signed();
    assert!(!signature(&bytes).verify(MSG, &pk));
}

#[test]
fn a_valid_signature_plus_a_non_subgroup_point_is_refused() {
    let (pk, sig) = signed();
    let s = G2Affine::from_compressed(&sig).unwrap();
    let q = G2Affine::from_compressed_unchecked(&non_subgroup_point()).unwrap();
    let forged = G2Affine::from(G2Projective::from(s) + q).to_compressed();
    assert!(bool::from(
        G2Affine::from_compressed_unchecked(&forged).is_some()
    ));
    assert!(!signature(&forged).verify(MSG, &pk));
}

#[test]
fn the_removed_helper_accepted_every_point() {
    // helios's subgroup_check_g2: point * Scalar::from_raw(r) == identity, with r the group order.
    let r = Scalar::from_raw([
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ]);
    assert_eq!(r, Scalar::zero());
    let outside = G2Affine::from_compressed_unchecked(&non_subgroup_point()).unwrap();
    assert!(bool::from((outside * r).is_identity()));
}
