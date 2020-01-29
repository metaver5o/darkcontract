use bls12_381 as bls;
use sha2::{Sha256, Digest};

use crate::bls_extensions::*;
use crate::coconut::{Attribute, VerifyKey};
use crate::elgamal::*;
use crate::parameters::*;

pub type SignerProof = (bls::Scalar, bls::Scalar, Vec<bls::Scalar>, Vec<bls::Scalar>);
pub type VerifyProof = (bls::Scalar, Vec<bls::Scalar>, bls::Scalar);

fn compute_challenge(points_g1: Vec<&bls::G1Projective>, points_g2: Vec<&bls::G2Projective>)
    -> bls::Scalar {
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

pub fn make_signer_proof<R: RngInstance>(params: &Parameters<R>, gamma: &ElGamalPublicKey<R>,
                     ciphertext: &Vec<EncryptedValue>, attribute_commit: &bls::G1Projective,
                     commit_hash: &bls::G1Projective, attribute_keys: &Vec<bls::Scalar>,
                     attributes: &Vec<Attribute>, blinding_factor: &bls::Scalar)
    -> SignerProof {
    assert_eq!(ciphertext.len(), attribute_keys.len());
    assert_eq!(ciphertext.len(), attributes.len());

    // Random witness
    let witness_blind = params.random_scalar();
    let witness_keys: Vec<_> = attribute_keys.iter().map(|_| params.random_scalar()).collect();
    let witness_attributes: Vec<_> = attributes.iter().map(|_| params.random_scalar()).collect();

    // Witness commit
    let witness_commit_a: Vec<_> =
        witness_keys.iter().map(|witness| params.g1 * witness).collect();
    let witness_commit_b: Vec<_> =
        witness_keys.iter().zip(witness_attributes.iter())
            .map(|(witness_key, witness_attribute)|
                 gamma.public_key * witness_key + commit_hash * witness_attribute).collect();

    assert_eq!(witness_attributes.len(), params.hs.len());
    let witness_commit_attributes =
        params.g1 * witness_blind
        + params.hs.iter().zip(witness_attributes.iter())
            .map(|(h, witness)| h * witness)
            .sum::<bls::G1Projective>();


    // Challenge
    let g1 = bls::G1Projective::from(params.g1);
    let hs: Vec<_> = params.hs.iter().map(|h| bls::G1Projective::from(h)).collect();
    let challenge = compute_challenge(
        {
            let mut points: Vec<&_> = vec![
                &g1,                                    // G1
                attribute_commit,                       // C_m
                commit_hash,                            // h
                &witness_commit_attributes              // Cw
            ];
            points.extend(witness_commit_a.iter());     // Aw
            points.extend(witness_commit_b.iter());     // Bw
            points.extend(hs.iter());                   // hs
            points
        },
        vec![&bls::G2Projective::from(params.g2)]  // G2
    );

    // Responses
    assert_eq!(witness_keys.len(), attribute_keys.len());
    assert_eq!(witness_attributes.len(), attributes.len());
    let response_blind = witness_blind - challenge * blinding_factor;
    let response_keys: Vec<_> =
        witness_keys.iter().zip(attribute_keys.iter())
            .map(|(witness, key)| witness - challenge * key)
            .collect();
    let response_attributes: Vec<_> =
        witness_attributes.iter().zip(attributes.iter())
            .map(|(witness, attribute)| witness - challenge * attribute)
            .collect();

    (challenge, response_blind, response_keys, response_attributes)
}

pub fn verify_signer_proof<R: RngInstance>(params: &Parameters<R>, gamma: &bls::G1Projective,
                                           ciphertext: &Vec<EncryptedValue>,
                                           attribute_commit: &bls::G1Projective,
                                           commit_hash: &bls::G1Projective,
                                           proof: &SignerProof) -> bool {
    let (a_factors, b_factors): (Vec<&_>, Vec<&_>) =
        ciphertext.iter().map(|(ref a, ref b)| (a, b)).unzip();
    let (challenge, response_blind, response_keys, response_attributes) = proof;

    // Recompute witness commitments
    assert_eq!(ciphertext.len(), response_keys.len());
    assert_eq!(a_factors.len(), response_keys.len());
    assert_eq!(b_factors.len(), response_keys.len());
    let witness_commit_a: Vec<_> =
        a_factors.iter().zip(response_keys.iter())
            .map(|(a_i, response)| *a_i * challenge + params.g1 * response).collect();
    let witness_commit_b: Vec<_> =
        b_factors.iter().zip(response_keys.iter()).zip(response_attributes.iter())
            .map(|((b_i, response_key), response_attribute)|
                 *b_i * challenge + gamma * response_key + commit_hash * response_attribute)
            .collect();
    let witness_commit_attributes =
        attribute_commit * challenge
        + params.g1 * response_blind
        + params.hs.iter()
            .zip(response_attributes.iter())
            .map(|(h_i, response)| h_i * response)
            .sum::<bls::G1Projective>();

    // Challenge
    let g1 = bls::G1Projective::from(params.g1);
    let hs: Vec<_> = params.hs.iter().map(|h| bls::G1Projective::from(h)).collect();
    let recomputed_challenge = compute_challenge(
        {
            let mut points: Vec<&_> = vec![
                &g1,                                    // G1
                attribute_commit,                       // C_m
                commit_hash,                            // h
                &witness_commit_attributes              // Cw
            ];
            points.extend(witness_commit_a.iter()); // Aw
            points.extend(witness_commit_b.iter()); // Bw
            points.extend(hs.iter());               // hs
            points
        },
        vec![&bls::G2Projective::from(params.g2)]       // G2
    );

    *challenge == recomputed_challenge
}

pub fn make_verify_proof<R: RngInstance>(params: &Parameters<R>,
                                         verify_key: &VerifyKey,
                                         blind_commit_hash: &bls::G1Projective,
                                         attributes: &Vec<bls::Scalar>,
                                         blind: &bls::Scalar) -> VerifyProof
{
    // Random witness
    let witness_kappa: Vec<_> = attributes.iter().map(|_| params.random_scalar()).collect();
    let witness_blind = params.random_scalar();

    // Witness commit
    assert_eq!(witness_kappa.len(), verify_key.beta.len());
    let witness_commit_kappa =
        params.g2 * witness_blind
        + verify_key.alpha
        + witness_kappa.iter()
            .zip(verify_key.beta.iter())
            .map(|(witness, beta_i)| beta_i * witness)
            .sum::<bls::G2Projective>();
    let witness_commit_blind = blind_commit_hash * witness_blind;

    // Challenge
    let g1 = bls::G1Projective::from(params.g1);
    let g2 = bls::G2Projective::from(params.g2);
    let hs: Vec<_> = params.hs.iter().map(|h| bls::G1Projective::from(h)).collect();
    let challenge = compute_challenge(
        {
            let mut points: Vec<&_> = vec![
                &g1,                                    // G1
                &witness_commit_blind,                  // Bw
            ];
            points.extend(hs.iter());                   // hs
            points
        },
        {
            let mut points: Vec<&_> = vec![
                &g2,                                    // G2
                &verify_key.alpha,                       // alpha
                &witness_commit_kappa                   // Aw
            ];
            points.extend(verify_key.beta.iter());                 // beta
            points
        }
    );

    // Responses
    assert_eq!(witness_kappa.len(), attributes.len());
    let response_kappa: Vec<_> =
        witness_kappa.iter().zip(attributes.iter())
            .map(|(witness, attribute)| witness - challenge * attribute)
            .collect();
    let response_blind = witness_blind - challenge * blind;
    (challenge, response_kappa, response_blind)
}

// TODO: should just accept credential
pub fn verify_verify_proof<R: RngInstance>(params: &Parameters<R>,
                                           verify_key: &VerifyKey,
                                           blind_commit_hash: &bls::G1Projective,
                                           kappa: &bls::G2Projective, v: &bls::G1Projective,
                                           proof: &VerifyProof) -> bool {
    let (challenge, response_kappa, response_blind) = proof;

    // Recompute witness commitments
    let witness_commit_kappa =
        kappa * challenge
        + params.g2 * response_blind
        + verify_key.alpha * (bls::Scalar::one() - challenge)
        + verify_key.beta.iter()
            .zip(response_kappa.iter())
            .map(|(beta_i, response)| beta_i * response)
            .sum::<bls::G2Projective>();
    let witness_commit_blind = v * challenge + blind_commit_hash * response_blind;

    // Challenge
    let g1 = bls::G1Projective::from(params.g1);
    let g2 = bls::G2Projective::from(params.g2);
    let hs: Vec<_> = params.hs.iter().map(|h| bls::G1Projective::from(h)).collect();
    let recomputed_challenge = compute_challenge(
        {
            let mut points: Vec<&_> = vec![
                &g1,                                    // G1
                &witness_commit_blind,                  // Bw
            ];
            points.extend(hs.iter());                   // hs
            points
        },
        {
            let mut points: Vec<&_> = vec![
                &g2,                                    // G2
                &verify_key.alpha,                                  // alpha
                &witness_commit_kappa                   // Aw
            ];
            points.extend(verify_key.beta.iter());                 // beta
            points
        }
    );

    *challenge == recomputed_challenge
}

