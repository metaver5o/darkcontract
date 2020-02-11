use bls12_381 as bls;

use crate::bls_extensions::*;
use crate::elgamal::*;
use crate::parameters::*;
use crate::proofs::credential_proof::*;
use crate::proofs::proof::*;
use crate::proofs::signature_proof::*;
use crate::utility::*;

pub struct SecretKey {
    pub x: bls::Scalar,
    pub y: Vec<bls::Scalar>,
}

pub struct VerifyKey {
    pub alpha: bls::G2Projective,
    pub beta: Vec<bls::G2Projective>,
}

pub type Attribute = bls::Scalar;

pub struct BlindSignatureRequest {
    attribute_commit: bls::G1Projective,
    encrypted_attributes: Vec<EncryptedValue>,
    challenge: bls::Scalar,
    proof: SignatureProof,
}

impl BlindSignatureRequest {
    pub fn compute_commit_hash(&self) -> bls::G1Projective {
        compute_commit_hash(&self.attribute_commit)
    }

    pub fn blind_sign<R: RngInstance>(
        &self,
        params: &Parameters<R>,
        secret_key: &SecretKey,
        shared_attribute_key: &ElGamalPublicKey<R>,
        external_commitments: Vec<Box<dyn ProofCommitments>>,
    ) -> Result<PartialSignature, &'static str> {
        assert_eq!(self.encrypted_attributes.len(), params.hs.len());
        let (a_factors, b_factors): (Vec<&_>, Vec<&_>) = self
            .encrypted_attributes
            .iter()
            .map(|value| (&value.0, &value.1))
            .unzip();

        // Issue signature
        let commit_hash = self.compute_commit_hash();

        // Verify proof
        let commitments = self.proof.commitments(
            params,
            &self.challenge,
            shared_attribute_key,
            &commit_hash,
            &self.attribute_commit,
            &self.encrypted_attributes,
        );
        let mut proof_assembly = ProofAssembly::new();
        proof_assembly.add(commitments);
        for commit in external_commitments {
            proof_assembly.add(commit);
        }

        // Challenge
        let challenge = proof_assembly.compute_challenge();

        if challenge != self.challenge {
            return Err("verify proof failed");
        }

        // TODO: Add public attributes - need to see about selective reveal
        let signature_a = secret_key
            .y
            .iter()
            .zip(a_factors.iter())
            .map(|(y_j, a)| *a * y_j)
            .sum();

        let signature_b = commit_hash * secret_key.x
            + secret_key
                .y
                .iter()
                .zip(b_factors.iter())
                .map(|(y_j, b)| *b * y_j)
                .sum::<bls::G1Projective>();

        Ok(PartialSignature { encrypted_value: (signature_a, signature_b) })
    }
}

type SignatureShare = bls::G1Projective;
type CombinedSignatureShares = bls::G1Projective;
type Signature = (bls::G1Projective, bls::G1Projective);

pub struct PartialSignature {
    encrypted_value: EncryptedValue
}

impl PartialSignature {
    pub fn unblind<R: RngInstance>(
        &self,
        private_key: &ElGamalPrivateKey<R>,
    ) -> SignatureShare {
        private_key.decrypt(&self.encrypted_value)
    }
}

pub struct SignatureX {
    commit_hash: bls::G1Projective,
    signature: bls::G1Projective,
}

pub struct Credential {
    kappa: bls::G2Projective,
    v: bls::G1Projective,
    blind_commit_hash: bls::G1Projective,
    blind_sigma: bls::G1Projective,
    challenge: bls::Scalar,
    proof: CredentialProof,
}

pub struct Coconut<R: RngInstance> {
    pub params: Parameters<R>,
    threshold: u32,
    authorities_total: u32,
}

impl<R: RngInstance> Coconut<R> {
    pub fn new(attributes_size: usize, authorities_threshold: u32, authorities_total: u32) -> Self {
        Self {
            params: Parameters::<R>::new(attributes_size),
            threshold: authorities_threshold,
            authorities_total: authorities_total,
        }
    }

    pub fn multiparty_keygen(&self) -> (Vec<SecretKey>, Vec<VerifyKey>) {
        let attributes_size = self.params.hs.len();
        assert!(self.authorities_total >= self.threshold);
        assert!(attributes_size > 0);

        let n_random_scalars = |n| (0..n).map(|_| self.params.random_scalar()).collect();
        let v_poly: Vec<_> = n_random_scalars(self.threshold);
        let w_poly: Vec<Vec<_>> = (0..attributes_size)
            .map(|_| n_random_scalars(self.threshold))
            .collect();

        //// Generate shares
        let x_shares =
            (1..=self.authorities_total).map(|i| compute_polynomial(v_poly.iter(), i as u64));
        let y_shares = (1..=self.authorities_total).map(|i| {
            w_poly
                .iter()
                .map(move |w_coefficients| compute_polynomial(w_coefficients.iter(), i as u64))
        });

        // Set the keys
        // sk_i = (x, (y_1, y_2, ..., y_q))
        // vk_i = (g2^x, (g2^y_1, g2^y_2, ..., g2^y_q)) = (a, (B_1, B_2, ..., B_q))
        let verify_keys: Vec<VerifyKey> = x_shares
            .clone()
            .zip(y_shares.clone())
            .map(|(x, y_share_parts)| VerifyKey {
                alpha: self.params.g2 * x,
                beta: y_share_parts.map(|y| self.params.g2 * y).collect(),
            })
            .collect();
        // We are moving out of x_shares into SecretKey, so this line happens
        // after creating verify_keys to avoid triggering borrow checker.
        let secret_keys: Vec<SecretKey> = x_shares
            .zip(y_shares)
            .map(|(x, y)| SecretKey {
                x: x,
                y: y.collect(),
            })
            .collect();

        (secret_keys, verify_keys)
    }

    pub fn aggregate_keys(&self, verify_keys: &Vec<VerifyKey>) -> VerifyKey {
        let lagrange = lagrange_basis_from_range(verify_keys.len() as u64);

        let (alpha, beta): (Vec<&_>, Vec<&Vec<_>>) = verify_keys
            .iter()
            .map(|key| (&key.alpha, &key.beta))
            .unzip();

        assert!(beta.len() > 0);
        let attributes_size = beta[0].len();

        assert_eq!(lagrange.len(), alpha.len());

        let aggregate_alpha = alpha.iter().zip(lagrange.iter()).map(|(a, l)| *a * l).sum();
        let aggregate_beta: Vec<_> = (0..attributes_size)
            .map(|i| {
                beta.iter()
                    .zip(lagrange.iter())
                    .map(|(b, l)| b[i] * l)
                    .sum()
            })
            .collect();

        return VerifyKey {
            alpha: aggregate_alpha,
            beta: aggregate_beta,
        };
    }

    pub fn make_blind_sign_request<'a>(
        &self,
        shared_attribute_key: &'a ElGamalPublicKey<R>,
        attributes: &'a Vec<Attribute>,
        external_commitments: Vec<Box<dyn ProofCommitments>>,
    ) -> BlindSignatureRequest {
        let blinding_factor = self.params.random_scalar();

        assert_eq!(self.params.hs.len(), attributes.len());
        let attribute_commit = self.params.g1 * blinding_factor
            + self
                .params
                .hs
                .iter()
                .zip(attributes.iter())
                .map(|(h_generator, attribute)| h_generator * attribute)
                .sum::<bls::G1Projective>();
        let commit_hash = compute_commit_hash(&attribute_commit);

        let attribute_keys: Vec<_> = (0..attributes.len())
            .map(|_| self.params.random_scalar())
            .collect();

        let encrypted_attributes: Vec<(_, _)> = attributes
            .iter()
            .zip(attribute_keys.iter())
            .map(|(attribute, key)| shared_attribute_key.encrypt(&attribute, &key, &commit_hash))
            .collect();

        // Construct proof
        // Witness
        let proof_builder =
            SignatureProofBuilder::new(&self.params, attributes, &attribute_keys, &blinding_factor);
        // Commits
        let commitments =
            proof_builder.commitments(shared_attribute_key, &commit_hash, &attribute_commit);

        let mut proof_assembly = ProofAssembly::new();
        proof_assembly.add(commitments);
        for commit in external_commitments {
            proof_assembly.add(commit);
        }

        // Challenge
        let challenge = proof_assembly.compute_challenge();
        //Responses
        let proof = proof_builder.finish(&challenge);

        BlindSignatureRequest {
            attribute_commit,
            encrypted_attributes,
            challenge,
            proof,
        }
    }

    pub fn aggregate(
        &self,
        signature_shares: &Vec<SignatureShare>,
        indexes: Vec<u64>,
    ) -> CombinedSignatureShares {
        let lagrange = lagrange_basis(indexes.iter());

        let aggregate_shares = signature_shares
            .iter()
            .zip(lagrange.iter())
            .map(|(signature_share, lagrange_i)| signature_share * lagrange_i)
            .sum();
        aggregate_shares
    }

    pub fn make_credential(
        &self,
        verify_key: &VerifyKey,
        signature: &Signature,
        attributes: &Vec<Attribute>,
        external_commitments: Vec<Box<dyn ProofCommitments>>,
    ) -> Credential {
        let (commit_hash, sigma) = signature;
        assert_eq!(attributes.len(), verify_key.beta.len());

        let blind_prime = self.params.random_scalar();
        let (blind_commit_hash, blind_sigma) = (commit_hash * blind_prime, sigma * blind_prime);

        let blind = self.params.random_scalar();

        let kappa = self.params.g2 * blind
            + verify_key.alpha
            + verify_key
                .beta
                .iter()
                .zip(attributes.iter())
                .map(|(beta_i, attribute)| beta_i * attribute)
                .sum::<bls::G2Projective>();
        let v = blind_commit_hash * blind;

        // Construct proof
        // Witness
        let proof_builder = CredentialProofBuilder::new(&self.params, attributes, &blind);
        // Commits
        let commitments = proof_builder.commitments(verify_key, &blind_commit_hash);

        let mut proof_assembly = ProofAssembly::new();
        proof_assembly.add(commitments);
        for commit in external_commitments {
            proof_assembly.add(commit);
        }

        // Challenge
        let challenge = proof_assembly.compute_challenge();
        //Responses
        let proof = proof_builder.finish(&challenge);

        Credential {
            kappa: kappa,
            v: v,
            blind_commit_hash,
            blind_sigma,
            challenge,
            proof,
        }
    }
}

impl Credential {
    pub fn verify<R: RngInstance>(
        &self,
        params: &Parameters<R>,
        verify_key: &VerifyKey,
        external_commitments: Vec<Box<dyn ProofCommitments>>,
    ) -> bool {
        let commitments = self.proof.commitments(
            params,
            &self.challenge,
            verify_key,
            &self.blind_commit_hash,
            &self.kappa,
            &self.v,
        );

        let mut proof_assembly = ProofAssembly::new();
        proof_assembly.add(commitments);
        for commit in external_commitments {
            proof_assembly.add(commit);
        }

        // Challenge
        let challenge = proof_assembly.compute_challenge();

        if challenge != self.challenge {
            return false;
        }

        let kappa = bls::G2Affine::from(self.kappa);
        let blind_commit = bls::G1Affine::from(self.blind_commit_hash);
        let sigma_nu = bls::G1Affine::from(self.blind_sigma + self.v);
        bls::pairing(&blind_commit, &kappa) == bls::pairing(&sigma_nu, &params.g2)
    }
}

