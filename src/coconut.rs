use bls12_381 as bls;

use crate::bls_extensions::*;
use crate::elgamal::*;
use crate::old_proofs::*;
use crate::parameters::*;
use crate::utility::*;

pub struct SecretKey {
    x: bls::Scalar,
    y: Vec<bls::Scalar>,
}

pub struct VerifyKey {
    pub alpha: bls::G2Projective,
    pub beta: Vec<bls::G2Projective>,
}

pub type Attribute = bls::Scalar;
pub type BlindSignatureRequest = (bls::G1Projective, Vec<EncryptedValue>, SignerProof);

type PartialSignature = (bls::G1Projective, bls::G1Projective);
type SignatureShare = bls::G1Projective;
type CombinedSignatureShares = bls::G1Projective;
type Signature = (bls::G1Projective, bls::G1Projective);

pub struct Credential {
    kappa: bls::G2Projective,
    v: bls::G1Projective,
    // sigma_price: (blind_commit_projective, blinded_sigma)
    sigma_prime: (bls::G1Projective, bls::G1Projective),
    proof: VerifyProof,
}

pub struct Coconut<R: RngInstance> {
    params: Parameters<R>,
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
            .map(|ref key| (&key.alpha, &key.beta))
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

    pub fn make_blind_sign_request(
        &self,
        shared_attribute_key: &ElGamalPublicKey<R>,
        attributes: &Vec<Attribute>,
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

        /*
        // Witness
        let proof_builder = SignatureProofBuilder::new(&params, &attributes,
                                                       &attribute_keys,
                                                       &blinding_factor);
        // Commits
        let commitments = proof_builder.commitments(shared_attribute_key, &commit_hash,
                                                    &attribute_commit);
        // Challenge
        let mut hasher = ProofHasher::new();
        commitments.commit(&mut hasher);
        let challenge = hasher.finish();
        //Responses
        let proof = proof_builder.finish(&challenge);
        */

        let signer_proof = make_signer_proof(
            &self.params,
            shared_attribute_key,
            &encrypted_attributes,
            &attribute_commit,
            &commit_hash,
            &attribute_keys,
            &attributes,
            &blinding_factor,
        );

        (attribute_commit, encrypted_attributes, signer_proof)
    }

    pub fn blind_sign(
        &self,
        secret_key: &SecretKey,
        shared_attribute_key: &ElGamalPublicKey<R>,
        sign_request: &BlindSignatureRequest,
    ) -> Result<PartialSignature, &'static str> {
        let (attribute_commit, encrypted_attributes, signer_proof) = sign_request;

        assert_eq!(encrypted_attributes.len(), self.params.hs.len());
        let (a_factors, b_factors): (Vec<&_>, Vec<&_>) = encrypted_attributes
            .iter()
            .map(|&(ref a, ref b)| (a, b))
            .unzip();

        // Issue signature
        let commit_hash = compute_commit_hash(attribute_commit);

        // Verify proof here
        if !verify_signer_proof(
            &self.params,
            &shared_attribute_key.public_key,
            encrypted_attributes,
            attribute_commit,
            &commit_hash,
            signer_proof,
        ) {
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

        Ok((signature_a, signature_b))
    }

    pub fn unblind(
        &self,
        private_key: &ElGamalPrivateKey<R>,
        encrypted_value: &EncryptedValue,
    ) -> SignatureShare {
        private_key.decrypt(encrypted_value)
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
    ) -> Credential {
        let (commit_hash, sigma) = signature;
        assert_eq!(attributes.len(), verify_key.beta.len());

        let blind_prime = self.params.random_scalar();
        let (blinded_commit_hash, blinded_sigma) = (commit_hash * blind_prime, sigma * blind_prime);

        let blind = self.params.random_scalar();

        let kappa = self.params.g2 * blind
            + verify_key.alpha
            + verify_key
                .beta
                .iter()
                .zip(attributes.iter())
                .map(|(beta_i, attribute)| beta_i * attribute)
                .sum::<bls::G2Projective>();
        let v = blinded_commit_hash * blind;

        let proof = make_verify_proof(
            &self.params,
            verify_key,
            &blinded_commit_hash,
            attributes,
            &blind,
        );

        Credential {
            kappa: kappa,
            v: v,
            sigma_prime: (blinded_commit_hash, blinded_sigma),
            proof,
        }
    }

    pub fn verify_credential(&self, verify_key: &VerifyKey, credential: &Credential) -> bool {
        if !verify_verify_proof(
            &self.params,
            verify_key,
            &credential.sigma_prime.0,
            &credential.kappa,
            &credential.v,
            &credential.proof,
        ) {
            return false;
        }
        let kappa = bls::G2Affine::from(credential.kappa);
        let blind_commit = bls::G1Affine::from(credential.sigma_prime.0);
        let sigma_nu = bls::G1Affine::from(credential.sigma_prime.1 + credential.v);
        bls::pairing(&blind_commit, &kappa) == bls::pairing(&sigma_nu, &self.params.g2)
    }
}

//extern crate hex_slice;
//use hex_slice::AsHex;

#[test]
fn test_multiparty_keygen() {
    let attributes_size = 2;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let sigs_x: Vec<bls::G1Projective> = secret_keys
        .iter()
        .map(|secret_key| coconut.params.g1 * secret_key.x)
        .collect();
    let l = lagrange_basis_from_range(6);
    let sig = &l
        .iter()
        .zip(sigs_x.iter())
        .map(|(l_i, s_i)| s_i * l_i)
        .sum();

    let ppair_1 = bls::pairing(&bls::G1Affine::from(sig), &coconut.params.g2);
    let ppair_2 = bls::pairing(&coconut.params.g1, &bls::G2Affine::from(verify_key.alpha));
    assert_eq!(ppair_1, ppair_2);
}

#[test]
fn test_multiparty_coconut() {
    let attributes_size = 2;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let d = ElGamalPrivateKey::new(&coconut.params);
    let gamma = d.to_public();

    let attributes = vec![bls::Scalar::from(110), bls::Scalar::from(4)];

    let sign_request = coconut.make_blind_sign_request(&gamma, &attributes);

    let blind_signatures: Vec<_> = secret_keys
        .iter()
        .map(|secret_key| {
            coconut
                .blind_sign(secret_key, &gamma, &sign_request)
                .unwrap()
        })
        .collect();

    // Signatures should be a struct, with an authority ID inside them
    let mut signature_shares: Vec<_> = blind_signatures
        .iter()
        .map(|blind_signature| coconut.unblind(&d, blind_signature))
        .collect();
    let mut indexes: Vec<u64> = (1u64..=signature_shares.len() as u64).collect();

    signature_shares.remove(0);
    indexes.remove(0);
    signature_shares.remove(4);
    indexes.remove(4);

    let commit_hash = compute_commit_hash(&sign_request.0);
    let signature = (commit_hash, coconut.aggregate(&signature_shares, indexes));

    let credential = coconut.make_credential(&verify_key, &signature, &attributes);

    let is_verify = coconut.verify_credential(&verify_key, &credential);
    assert!(is_verify);
}
