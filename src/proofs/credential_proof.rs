use bls12_381 as bls;
use itertools::izip;

use crate::bls_extensions::*;
use crate::coconut::*;
use crate::parameters::*;
use crate::proofs::proof::*;

pub struct CredentialProofBuilder<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    // Secrets
    attributes: &'a Vec<bls::Scalar>,
    blind: &'a bls::Scalar,

    // Witnesses
    witness_kappa: Vec<bls::Scalar>,
    witness_blind: bls::Scalar,
}

pub struct CredentialProofCommitments<'a, R: RngInstance> {
    // Base points
    params: &'a Parameters<R>,
    verify_key: &'a VerifyKey,
    blind_commit_hash: &'a bls::G1Projective,

    // Commitments
    commit_kappa: bls::G2Projective,
    commit_blind: bls::G1Projective
}

pub struct CredentialProof<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    response_kappa: Vec<bls::Scalar>,
    response_blind: bls::Scalar
}

impl<'a, R: RngInstance> CredentialProofBuilder<'a, R> {
    pub fn new(
        params: &'a Parameters<R>,
        attributes: &'a Vec<bls::Scalar>,
        blind: &'a bls::Scalar,
    ) -> Self {
        Self {
            params,

            attributes,
            blind,

            witness_kappa: params.random_scalars(attributes.len()),
            witness_blind: params.random_scalar()
        }
    }

    pub fn commitments (
        &self,
        verify_key: &'a VerifyKey,
        blind_commit_hash: &'a bls::G1Projective,
    ) -> CredentialProofCommitments<'a, R> {
        assert_eq!(self.witness_kappa.len(), verify_key.beta.len());

        CredentialProofCommitments {
            params: self.params,
            verify_key,
            blind_commit_hash,

            commit_kappa: self.params.g2 * self.witness_blind + verify_key.alpha
                + self.witness_kappa
                    .iter()
                    .zip(verify_key.beta.iter())
                    .map(|(witness, beta_i)| beta_i * witness)
                    .sum::<bls::G2Projective>(),

            commit_blind: blind_commit_hash * self.witness_blind,
        }
    }

    pub fn finish(&self, challenge: &bls::Scalar) -> CredentialProof<'a, R> {
        assert_eq!(self.witness_kappa.len(), self.attributes.len());

        CredentialProof {
            params: self.params,

            response_kappa: izip!(&self.witness_kappa, self.attributes)
                .map(|(witness, attribute)| witness - challenge * attribute)
                .collect(),

            response_blind: self.witness_blind - challenge * self.blind,
        }
    }
}

impl<'a, R: RngInstance> CredentialProofCommitments<'a, R> {
    pub fn commit(&self, hasher: &mut ProofHasher) {
        // Add base points we use
        hasher.add_g1_affine(&self.params.g1);
        hasher.add_g2_affine(&self.params.g2);
        for h in &self.params.hs {
            hasher.add_g1_affine(h);
        }
        hasher.add_g2(&self.verify_key.alpha);
        for beta in &self.verify_key.beta {
            hasher.add_g2(beta);
        }

        hasher.add_g2(&self.commit_kappa);
        hasher.add_g1(&self.commit_blind);
    }
}

impl<'a, R: RngInstance> CredentialProof<'a, R> {
    pub fn commitments(
        &self,
        challenge: &bls::Scalar,
        verify_key: &'a VerifyKey,
        blind_commit_hash: &'a bls::G1Projective,
        kappa: &bls::G2Projective,
        v: &bls::G1Projective,
    ) -> CredentialProofCommitments<R> {

        // c K + r_t G2 + (1 - c) A + sum(r_m_i B_i)
        let mut commit_kappa = kappa * challenge + self.params.g2 * self.response_blind
            + verify_key.alpha * (bls::Scalar::one() - challenge);
        for (beta_i, response) in izip!(&verify_key.beta, &self.response_kappa) {
            commit_kappa += beta_i * response;
        }

        CredentialProofCommitments {
            params: self.params,
            verify_key,
            blind_commit_hash,

            commit_kappa,

            commit_blind: v * challenge + blind_commit_hash * self.response_blind
        }
    }
}

