use hex_slice::AsHex;
use bls12_381 as bls;
use itertools::izip;
use sha2::{Digest, Sha256};

use crate::bls_extensions::*;
use crate::coconut::{Attribute, VerifyKey};
use crate::elgamal::*;
use crate::parameters::*;
use crate::utility::*;

pub type SignerProof = (bls::Scalar, bls::Scalar, Vec<bls::Scalar>, Vec<bls::Scalar>);
pub type VerifyProof = (bls::Scalar, Vec<bls::Scalar>, bls::Scalar);

fn compute_challenge(
    points_g1: Vec<&bls::G1Projective>,
    points_g2: Vec<&bls::G2Projective>,
) -> bls::Scalar {
    for i in 0u32.. {
        let mut hasher = Sha256::new();

        let i_data = i.to_le_bytes();
        hasher.input(&i_data);

        for point in &points_g1 {
            let data = bls::G1Affine::from(*point).to_compressed();
            hasher.input(&data[0..32]);
            hasher.input(&data[32..]);
        }
        for point in &points_g2 {
            let data = bls::G2Affine::from(*point).to_compressed();
            hasher.input(&data[0..32]);
            hasher.input(&data[32..64]);
            hasher.input(&data[64..]);
        }
        let hash_result = hasher.result();

        // TODO: how can I fix this? Why not &hash_result[0...32]??
        let mut hash_data = [0u8; 32];
        hash_data.copy_from_slice(hash_result.as_slice());

        let challenge = bls::Scalar::from_bytes(&hash_data);
        if challenge.is_some().unwrap_u8() == 1 {
            return challenge.unwrap();
        }
    }
    unreachable!();
}

pub fn make_signer_proof<R: RngInstance>(
    params: &Parameters<R>,
    gamma: &ElGamalPublicKey<R>,
    ciphertext: &Vec<EncryptedValue>,
    attribute_commit: &bls::G1Projective,
    commit_hash: &bls::G1Projective,
    attribute_keys: &Vec<bls::Scalar>,
    attributes: &Vec<Attribute>,
    blinding_factor: &bls::Scalar,
) -> SignerProof {

    /*
    for attribute in attributes {
        println!("attr: {:?}", attribute);
    }
    for attribute in attribute_keys {
        println!("attr keys: {:?}", attribute);
    }
    println!("blinding factor: {:?}", blinding_factor);

    let gpk = bls::G1Affine::from(gamma.public_key).to_compressed();
    println!("gamma: {:02x}", gpk.as_hex());
    let acc = bls::G1Affine::from(attribute_commit).to_compressed();
    println!("attribute_commit: {:02x}", acc.as_hex());
    let ccc = bls::G1Affine::from(commit_hash).to_compressed();
    println!("commit_hash: {:02x}", ccc.as_hex());
    for ciphert in ciphertext {
        let c0 = bls::G1Affine::from(ciphert.0).to_compressed();
        println!("ciphertext 0: {:02x}", c0.as_hex());
        let c1 = bls::G1Affine::from(ciphert.1).to_compressed();
        println!("ciphertext 1: {:02x}", c1.as_hex());
    }
    */

    assert_eq!(ciphertext.len(), attribute_keys.len());
    assert_eq!(ciphertext.len(), attributes.len());

    // Random witness
    let witness_blind = params.random_scalar();
    let witness_keys: Vec<_> = attribute_keys
        .iter()
        .map(|_| params.random_scalar())
        .collect();
    let witness_attributes: Vec<_> = attributes.iter().map(|_| params.random_scalar()).collect();

    // Witness commit
    let witness_commit_a: Vec<_> = witness_keys
        .iter()
        .map(|witness| params.g1 * witness)
        .collect();
    let witness_commit_b: Vec<_> = witness_keys
        .iter()
        .zip(witness_attributes.iter())
        .map(|(witness_key, witness_attribute)| {
            gamma.public_key * witness_key + commit_hash * witness_attribute
        })
        .collect();

    assert_eq!(witness_attributes.len(), params.hs.len());
    let witness_commit_attributes = params.g1 * witness_blind
        + params
            .hs
            .iter()
            .zip(witness_attributes.iter())
            .map(|(h, witness)| h * witness)
            .sum::<bls::G1Projective>();

    // Challenge
    let g1 = bls::G1Projective::from(params.g1);
    let hs: Vec<_> = params
        .hs
        .iter()
        .map(|h| bls::G1Projective::from(h))
        .collect();
    let challenge = compute_challenge(
        {
            let mut points: Vec<&_> = vec![
                &g1,                        // G1
                attribute_commit,           // C_m
                commit_hash,                // h
                &witness_commit_attributes, // Cw
            ];
            points.extend(witness_commit_a.iter()); // Aw
            points.extend(witness_commit_b.iter()); // Bw
            points.extend(hs.iter()); // hs
            points
        },
        vec![&bls::G2Projective::from(params.g2)], // G2
    );

    // Responses
    assert_eq!(witness_keys.len(), attribute_keys.len());
    assert_eq!(witness_attributes.len(), attributes.len());
    let response_blind = witness_blind - challenge * blinding_factor;
    let response_keys: Vec<_> = witness_keys
        .iter()
        .zip(attribute_keys.iter())
        .map(|(witness, key)| witness - challenge * key)
        .collect();
    let response_attributes: Vec<_> = witness_attributes
        .iter()
        .zip(attributes.iter())
        .map(|(witness, attribute)| witness - challenge * attribute)
        .collect();

    (
        challenge,
        response_blind,
        response_keys,
        response_attributes,
    )
}

pub fn verify_signer_proof<R: RngInstance>(
    params: &Parameters<R>,
    gamma: &bls::G1Projective,
    ciphertext: &Vec<EncryptedValue>,
    attribute_commit: &bls::G1Projective,
    commit_hash: &bls::G1Projective,
    proof: &SignerProof,
) -> bool {
    let (a_factors, b_factors): (Vec<&_>, Vec<&_>) =
        ciphertext.iter().map(|(ref a, ref b)| (a, b)).unzip();
    let (challenge, response_blind, response_keys, response_attributes) = proof;

    // Recompute witness commitments
    assert_eq!(ciphertext.len(), response_keys.len());
    assert_eq!(a_factors.len(), response_keys.len());
    assert_eq!(b_factors.len(), response_keys.len());
    let witness_commit_a: Vec<_> = a_factors
        .iter()
        .zip(response_keys.iter())
        .map(|(a_i, response)| *a_i * challenge + params.g1 * response)
        .collect();
    let witness_commit_b: Vec<_> = b_factors
        .iter()
        .zip(response_keys.iter())
        .zip(response_attributes.iter())
        .map(|((b_i, response_key), response_attribute)| {
            *b_i * challenge + gamma * response_key + commit_hash * response_attribute
        })
        .collect();
    let witness_commit_attributes = attribute_commit * challenge
        + params.g1 * response_blind
        + params
            .hs
            .iter()
            .zip(response_attributes.iter())
            .map(|(h_i, response)| h_i * response)
            .sum::<bls::G1Projective>();

    // Challenge
    let g1 = bls::G1Projective::from(params.g1);
    let hs: Vec<_> = params
        .hs
        .iter()
        .map(|h| bls::G1Projective::from(h))
        .collect();
    let recomputed_challenge = compute_challenge(
        {
            let mut points: Vec<&_> = vec![
                &g1,                        // G1
                attribute_commit,           // C_m
                commit_hash,                // h
                &witness_commit_attributes, // Cw
            ];
            points.extend(witness_commit_a.iter()); // Aw
            points.extend(witness_commit_b.iter()); // Bw
            points.extend(hs.iter()); // hs
            points
        },
        vec![&bls::G2Projective::from(params.g2)], // G2
    );

    *challenge == recomputed_challenge
}

pub fn make_verify_proof<R: RngInstance>(
    params: &Parameters<R>,
    verify_key: &VerifyKey,
    blind_commit_hash: &bls::G1Projective,
    attributes: &Vec<bls::Scalar>,
    blind: &bls::Scalar,
) -> VerifyProof {

    /*
    let cc = bls::G1Affine::from(blind_commit_hash).to_compressed();
    println!("blind_commit_hash: {:02x}", cc.as_hex());
    //let ac = bls::G1Affine::from(attribute_commit).to_compressed();
    //println!("attribute_commit: {:02x}", ac.as_hex());
    println!("blind: {:?}", blind);
    let vk = bls::G2Affine::from(verify_key.alpha).to_compressed();
    println!("alpha: {:02x}", vk.as_hex());
    for beta in &verify_key.beta {
        let bvk = bls::G2Affine::from(beta).to_compressed();
        println!("beta: {:02x}", bvk.as_hex());
    }
    */

    // Random witness
    let witness_kappa: Vec<_> = attributes.iter().map(|_| params.random_scalar()).collect();
    let witness_blind = params.random_scalar();

    // Witness commit
    assert_eq!(witness_kappa.len(), verify_key.beta.len());
    let witness_commit_kappa = params.g2 * witness_blind
        + verify_key.alpha
        + witness_kappa
            .iter()
            .zip(verify_key.beta.iter())
            .map(|(witness, beta_i)| beta_i * witness)
            .sum::<bls::G2Projective>();
    let witness_commit_blind = blind_commit_hash * witness_blind;

    // Challenge
    let g1 = bls::G1Projective::from(params.g1);
    let g2 = bls::G2Projective::from(params.g2);
    let hs: Vec<_> = params
        .hs
        .iter()
        .map(|h| bls::G1Projective::from(h))
        .collect();
    let challenge = compute_challenge(
        {
            let mut points: Vec<&_> = vec![
                &g1,                   // G1
                &witness_commit_blind, // Bw
            ];
            points.extend(hs.iter()); // hs
            points
        },
        {
            let mut points: Vec<&_> = vec![
                &g2,                   // G2
                &verify_key.alpha,     // alpha
                &witness_commit_kappa, // Aw
            ];
            points.extend(verify_key.beta.iter()); // beta
            points
        },
    );

    // Responses
    assert_eq!(witness_kappa.len(), attributes.len());
    let response_kappa: Vec<_> = witness_kappa
        .iter()
        .zip(attributes.iter())
        .map(|(witness, attribute)| witness - challenge * attribute)
        .collect();
    let response_blind = witness_blind - challenge * blind;
    (challenge, response_kappa, response_blind)
}

// TODO: should just accept credential
pub fn verify_verify_proof<R: RngInstance>(
    params: &Parameters<R>,
    verify_key: &VerifyKey,
    blind_commit_hash: &bls::G1Projective,
    kappa: &bls::G2Projective,
    v: &bls::G1Projective,
    proof: &VerifyProof,
) -> bool {

    /*
    let kk = bls::G2Affine::from(kappa).to_compressed();
    println!("kappa: {:02x}", kk.as_hex());
    let vk = bls::G1Affine::from(v).to_compressed();
    println!("v: {:02x}", vk.as_hex());
    */

    let (challenge, response_kappa, response_blind) = proof;

    // Recompute witness commitments
    let witness_commit_kappa = kappa * challenge
        + params.g2 * response_blind
        + verify_key.alpha * (bls::Scalar::one() - challenge)
        + verify_key
            .beta
            .iter()
            .zip(response_kappa.iter())
            .map(|(beta_i, response)| beta_i * response)
            .sum::<bls::G2Projective>();
    let witness_commit_blind = v * challenge + blind_commit_hash * response_blind;

    // Challenge
    let g1 = bls::G1Projective::from(params.g1);
    let g2 = bls::G2Projective::from(params.g2);
    let hs: Vec<_> = params
        .hs
        .iter()
        .map(|h| bls::G1Projective::from(h))
        .collect();
    let recomputed_challenge = compute_challenge(
        {
            let mut points: Vec<&_> = vec![
                &g1,                   // G1
                &witness_commit_blind, // Bw
            ];
            points.extend(hs.iter()); // hs
            points
        },
        {
            let mut points: Vec<&_> = vec![
                &g2,                   // G2
                &verify_key.alpha,     // alpha
                &witness_commit_kappa, // Aw
            ];
            points.extend(verify_key.beta.iter()); // beta
            points
        },
    );

    *challenge == recomputed_challenge
}

#[test]
fn test_signature_request_proof() {
    let params = Parameters::<OsRngInstance>::new(2);

    let attributes = vec![bls::Scalar::from(110), bls::Scalar::from(4)];

    let attribute_keys = vec![
        bls::Scalar::from_bytes(&[
            0xec, 0x37, 0x03, 0x7b, 0x33, 0xf4, 0x5c, 0x2e,
            0xd0, 0x56, 0xf2, 0x46, 0x43, 0xa0, 0xee, 0x01,
            0xfb, 0x77, 0xf1, 0xec, 0x95, 0x4b, 0xf2, 0xe5,
            0x62, 0x32, 0xb5, 0x4e, 0x27, 0xeb, 0xe9, 0x3f
        ]).unwrap(),

        bls::Scalar::from_bytes(&[
            0xe2, 0x88, 0x9a, 0x7c, 0xc9, 0x37, 0x4d, 0x12,
            0x12, 0x92, 0xcb, 0xcd, 0x6c, 0x4e, 0x93, 0x63,
            0x5a, 0xce, 0x40, 0x14, 0x4f, 0xfc, 0xc8, 0x0b,
            0x4c, 0x57, 0x65, 0x63, 0x65, 0x49, 0xb2, 0x59
        ]).unwrap(),
    ];

    let blinding_factor = bls::Scalar::from_bytes(&[
        0xbd, 0x48, 0x8f, 0xcd, 0xf7, 0x08, 0xd1, 0x36,
        0xee, 0x9f, 0xc7, 0xb1, 0xf6, 0x91, 0xde, 0xf5,
        0xc5, 0xfc, 0x48, 0x7c, 0x64, 0x58, 0xad, 0x01,
        0x29, 0xb4, 0xd8, 0x1c, 0xeb, 0xe2, 0x12, 0x5a
    ]).unwrap();

    let gamma = ElGamalPublicKey {
        params: &params,
        public_key: bls::G1Projective::from(bls::G1Affine::from_compressed(&[
            0xb6, 0xdf, 0x9e, 0x19, 0xbd, 0xca, 0x01, 0xb9,
            0x67, 0xe4, 0xf6, 0xff, 0x1d, 0x07, 0x53, 0x3a,
            0x50, 0x48, 0x7a, 0x71, 0x23, 0xa1, 0x06, 0xd3,
            0xd8, 0xa1, 0x29, 0x43, 0xee, 0xbe, 0x24, 0x58,
            0x9b, 0x93, 0xd7, 0x0b, 0xc6, 0xdc, 0x24, 0xaa,
            0x56, 0x56, 0x7d, 0x49, 0xd6, 0x6f, 0x31, 0x3e
        ]).unwrap())
    };

    let attribute_commit = bls::G1Projective::from(bls::G1Affine::from_compressed(&[
        0x97, 0x95, 0xba, 0x53, 0xe8, 0xbf, 0x83, 0xbd,
        0xf3, 0x23, 0xc6, 0xc9, 0x17, 0x4a, 0x41, 0xad,
        0xf5, 0x04, 0xdf, 0x3e, 0x49, 0x11, 0x76, 0x74,
        0xac, 0xcb, 0x24, 0xe6, 0xc5, 0x1a, 0x3e, 0xfc,
        0x1f, 0x24, 0x43, 0x0c, 0xce, 0x82, 0x6e, 0x78,
        0xc8, 0x65, 0xfc, 0x7e, 0xfc, 0x45, 0xf4, 0xfb
    ]).unwrap());

    let commit_hash = bls::G1Projective::from(bls::G1Affine::from_compressed(&[
        0x83, 0xe8, 0x9d, 0x58, 0xb1, 0x54, 0x48, 0xfa,
        0xd4, 0x59, 0x6e, 0x88, 0x42, 0xc7, 0x19, 0xd4,
        0x65, 0xa8, 0x53, 0xec, 0x87, 0xfe, 0xf5, 0xc3,
        0xdc, 0x4e, 0x13, 0xaa, 0x5d, 0xb0, 0x3e, 0xa6,
        0x0a, 0x1f, 0x22, 0xea, 0x65, 0xaa, 0xd2, 0xc5,
        0x55, 0xed, 0x37, 0xda, 0x44, 0x41, 0x55, 0x93
    ]).unwrap());

    let ciphertext = vec![
        (
            bls::G1Projective::from(bls::G1Affine::from_compressed(&[
                0x96, 0xbb, 0x5f, 0xe1, 0x01, 0xc9, 0x69, 0x97,
                0x3f, 0xb1, 0x74, 0x41, 0xae, 0x98, 0xcb, 0x99,
                0x8e, 0x70, 0x50, 0x8d, 0x32, 0x29, 0x91, 0x5e,
                0xaa, 0xb3, 0xba, 0xd6, 0x3a, 0xa4, 0x96, 0x49,
                0xf4, 0x63, 0xaa, 0x0d, 0x20, 0x60, 0x38, 0x27,
                0x76, 0x6d, 0x4b, 0x4a, 0xfc, 0xcd, 0x8a, 0x3c
            ]).unwrap()),
            bls::G1Projective::from(bls::G1Affine::from_compressed(&[
                0xb9, 0xae, 0x56, 0x13, 0xd9, 0xbc, 0x2d, 0xb1,
                0xeb, 0x82, 0x4d, 0x91, 0x99, 0xdc, 0x27, 0x33,
                0xae, 0x68, 0x87, 0x2c, 0x8a, 0xfc, 0xed, 0xbe,
                0x9c, 0x2f, 0x37, 0x19, 0x6a, 0xb3, 0xf9, 0x05,
                0x8d, 0x57, 0xc9, 0x08, 0x79, 0x51, 0xf9, 0x5e,
                0x2d, 0xae, 0x7d, 0x46, 0x90, 0xe6, 0xac, 0x42
            ]).unwrap())
        ),
        (
            bls::G1Projective::from(bls::G1Affine::from_compressed(&[
                0x8d, 0x66, 0x78, 0xda, 0x17, 0xcc, 0x6f, 0xa1,
                0x96, 0xa7, 0x7f, 0x6d, 0x0f, 0x29, 0x5f, 0x01,
                0x34, 0x14, 0xec, 0x38, 0xf2, 0x81, 0xc6, 0xea,
                0x0d, 0x83, 0xe6, 0xb8, 0x40, 0x63, 0x07, 0xf2,
                0x9a, 0x6f, 0x24, 0x66, 0x5f, 0x22, 0x5f, 0xb4,
                0xa3, 0x0c, 0xae, 0x09, 0x29, 0xa4, 0xdd, 0x45
            ]).unwrap()),
            bls::G1Projective::from(bls::G1Affine::from_compressed(&[
                0x96, 0xfd, 0xfe, 0xf3, 0x56, 0x86, 0x6f, 0xa3,
                0x82, 0x7a, 0x90, 0x9f, 0x76, 0xa8, 0xf2, 0x13,
                0x27, 0xb7, 0x4a, 0xb3, 0xd7, 0x32, 0xc7, 0xb8,
                0xbb, 0xf6, 0x7a, 0x29, 0xf6, 0x23, 0xc8, 0xfa,
                0x3d, 0x93, 0x05, 0x05, 0xc8, 0x74, 0x7b, 0x75,
                0x74, 0xa9, 0x4e, 0x7b, 0x03, 0x49, 0x5c, 0xbc
            ]).unwrap())
        )
    ];

    let blind_commit_hash = bls::G1Projective::from(bls::G1Affine::from_compressed(&[
        0x80, 0x81, 0xc6, 0xfb, 0x9b, 0x59, 0x80, 0xd6,
        0xf7, 0xbf, 0x51, 0xb9, 0xff, 0x76, 0x02, 0x44,
        0x6e, 0xed, 0xd2, 0x23, 0x74, 0xf5, 0x11, 0x5e,
        0x39, 0x09, 0xfc, 0x95, 0x09, 0x25, 0x1d, 0x0c,
        0xdd, 0x2a, 0xb1, 0x8d, 0x68, 0x18, 0x60, 0x1e,
        0x8f, 0x85, 0x94, 0x12, 0xaf, 0x01, 0x80, 0x24
    ]).unwrap());

    let blind = bls::Scalar::from_bytes(&[
        0x2e, 0xcf, 0x05, 0x0d, 0x66, 0xb3, 0xba, 0xb8,
        0x07, 0x3e, 0xbe, 0xad, 0xe1, 0x9d, 0xa6, 0x85,
        0xca, 0xb8, 0xfd, 0x98, 0xfa, 0x07, 0x45, 0xcb,
        0xb4, 0x15, 0x3c, 0x1d, 0x46, 0xcf, 0xd5, 0x39
    ]).unwrap();

    let verify_key = VerifyKey{
        alpha: bls::G2Projective::from(bls::G2Affine::from_compressed(&[
            0xad, 0x30, 0xc8, 0xe1, 0xd4, 0x5b, 0x3a, 0x3e,
            0xa3, 0xc3, 0xf0, 0x82, 0x3f, 0x30, 0x0d, 0xac,
            0x51, 0x8d, 0x3b, 0x10, 0xb3, 0x3e, 0x8b, 0xdf,
            0x9b, 0x80, 0x6d, 0x4d, 0x8b, 0xe9, 0x97, 0x69,
            0x42, 0xee, 0x67, 0xdd, 0x27, 0x19, 0x82, 0xd7,
            0x93, 0x49, 0x36, 0x6a, 0x26, 0x21, 0xae, 0xbc,
            0x16, 0xdc, 0x38, 0x7f, 0xb0, 0x27, 0xfa, 0x48,
            0x67, 0x6a, 0x7a, 0xff, 0x9f, 0xed, 0xf9, 0xdb,
            0x02, 0x6e, 0x3f, 0x4a, 0x9a, 0x93, 0x99, 0x0d,
            0xfe, 0x07, 0xd0, 0x72, 0x56, 0xbd, 0xd2, 0x38,
            0x1c, 0xf4, 0xb2, 0x54, 0xb3, 0xa1, 0x72, 0xa1,
            0x90, 0x16, 0x81, 0x31, 0xb0, 0xf5, 0xbe, 0xac
        ]).unwrap()),

        beta: vec![
            bls::G2Projective::from(bls::G2Affine::from_compressed(&[
                0xaa, 0x9d, 0xb9, 0xd8, 0x7a, 0x33, 0x07, 0xb2,
                0xb7, 0x44, 0xd9, 0xa8, 0x16, 0x86, 0xf3, 0x60,
                0x1b, 0xe3, 0xfe, 0x08, 0x85, 0xc1, 0x6b, 0x0a,
                0xea, 0xf2, 0x0a, 0xee, 0xaf, 0x46, 0xc5, 0x39,
                0x6e, 0x06, 0x1e, 0x05, 0x34, 0x2a, 0xea, 0x41,
                0xa1, 0xaf, 0xea, 0xff, 0x46, 0x0d, 0xa8, 0x7c,
                0x04, 0xa1, 0xbd, 0x26, 0x40, 0x50, 0x59, 0x1e,
                0xde, 0x1d, 0x13, 0xfc, 0x13, 0x79, 0x9f, 0x8c,
                0x31, 0x86, 0xef, 0x09, 0x0e, 0x24, 0x01, 0xb3,
                0x69, 0x2b, 0xef, 0x94, 0x13, 0xec, 0xe9, 0x21,
                0xb8, 0x70, 0x9a, 0x54, 0x71, 0xc8, 0x0f, 0x51,
                0x24, 0x95, 0xaf, 0xfb, 0x49, 0x08, 0xa0, 0xfa
            ]).unwrap()),

            bls::G2Projective::from(bls::G2Affine::from_compressed(&[
                0xae, 0xbd, 0x93, 0x0e, 0x7c, 0x57, 0x44, 0xf2,
                0x12, 0xfd, 0x3c, 0x60, 0xc5, 0x08, 0xa5, 0x13,
                0x7d, 0x92, 0x2b, 0x4c, 0x37, 0x3c, 0x99, 0x9f,
                0x33, 0xad, 0x49, 0x50, 0x62, 0x45, 0xd8, 0x6d,
                0x02, 0x41, 0x14, 0x2d, 0x34, 0x4c, 0xa5, 0x6d,
                0x1e, 0x67, 0x61, 0x7c, 0x74, 0x68, 0x92, 0xfd,
                0x09, 0xdb, 0xba, 0xdd, 0x77, 0x80, 0x89, 0xf6,
                0xb1, 0x70, 0x16, 0x59, 0xc5, 0x7a, 0x92, 0xca,
                0xa3, 0x91, 0xd3, 0xb4, 0x92, 0xcf, 0xb5, 0x97,
                0x80, 0xa2, 0x5b, 0x18, 0x18, 0x04, 0xbe, 0x24,
                0x57, 0xf6, 0x0a, 0x44, 0x54, 0xa3, 0x57, 0x36,
                0x49, 0x44, 0x3f, 0x0f, 0xd3, 0x7c, 0x79, 0x14
            ]).unwrap())
        ]
    };

    let kappa = bls::G2Projective::from(bls::G2Affine::from_compressed(&[
        0x89, 0x59, 0x75, 0x07, 0x43, 0x5d, 0x40, 0xf9,
        0x34, 0x7f, 0x2c, 0x03, 0xd3, 0x05, 0xd6, 0x98,
        0xd1, 0xe3, 0x4d, 0xd8, 0xcb, 0x1b, 0x7d, 0x97,
        0x46, 0x35, 0xeb, 0x86, 0xfe, 0x4c, 0x2b, 0x2a,
        0x49, 0x50, 0xd9, 0x50, 0x5f, 0x07, 0xd2, 0x7f,
        0xd3, 0x10, 0x66, 0x2d, 0x48, 0xeb, 0x77, 0xe3,
        0x18, 0x91, 0xbb, 0xe6, 0xd4, 0xe8, 0x52, 0x44,
        0x02, 0xeb, 0xf1, 0x88, 0x9a, 0x46, 0x1d, 0x80,
        0x90, 0x73, 0x4d, 0xa2, 0x28, 0xa1, 0xac, 0x71,
        0x12, 0x3b, 0x42, 0x38, 0xea, 0xc7, 0xae, 0x24,
        0xdb, 0x03, 0x13, 0x89, 0x9b, 0x6b, 0xcb, 0x45,
        0xe4, 0x3e, 0x12, 0x8c, 0xf2, 0xa5, 0x3c, 0xda
    ]).unwrap());

    let v = bls::G1Projective::from(bls::G1Affine::from_compressed(&[
        0x94, 0xc1, 0x76, 0xfb, 0x7a, 0xef, 0x48, 0x63,
        0x50, 0xe5, 0x80, 0xa3, 0xdd, 0x80, 0x4d, 0x60,
        0x59, 0x2d, 0x78, 0x7e, 0x44, 0x7d, 0x18, 0x83,
        0xee, 0x30, 0x40, 0x1f, 0x46, 0x03, 0x61, 0x0d,
        0x90, 0xa8, 0xe5, 0x32, 0x0a, 0xe6, 0x3c, 0x97,
        0x27, 0x2f, 0xd1, 0xa3, 0xa9, 0x09, 0x31, 0xbd
    ]).unwrap());

    // old stuff
    let sign_proof = make_signer_proof(&params, &gamma, &ciphertext,
                                       &attribute_commit, &commit_hash,
                                       &attribute_keys, &attributes,
                                       &blinding_factor);
    let sign_proof_verify = verify_signer_proof(&params, &gamma.public_key, &ciphertext,
                                                &attribute_commit, &commit_hash,
                                                &sign_proof);
    assert!(sign_proof_verify);

    let verify_proof = make_verify_proof(&params, &verify_key, &blind_commit_hash,
                                         &attributes, &blind);
    let verify_proof_verify = verify_verify_proof(&params, &verify_key, &blind_commit_hash,
                                                  &kappa, &v, &verify_proof);
    assert!(verify_proof_verify);
}

