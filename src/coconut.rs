use bls12_381 as bls;

use crate::bls_extensions::*;
use crate::elgamal::*;
use crate::parameters::*;

//type ScalarList = Vec<bls::Scalar>;
//type PointList = Vec<bls::G2Projective>;
//type VerifyKey = (bls::G2Projective, PointList);
//type SecretKey = (bls::Scalar, ScalarList);
//type Attribute = bls::Scalar;
//type LambdaType = (bls::G1Projective, Vec<EncryptedValue>, SignerProof);

//type SignerProof = (bls::Scalar, bls::Scalar, Vec<bls::Scalar>, Vec<bls::Scalar>);
//type VerifyProof = (bls::Scalar, Vec<bls::Scalar>, bls::Scalar);

//type SignatureShare = bls::G1Projective;
//type CombinedSignatureShares = bls::G1Projective;
//type Signature = (bls::G1Projective, bls::G1Projective);

//struct Credential {
//    kappa: bls::G2Projective,
//    v: bls::G1Projective,
//    sigma_prime: (bls::G1Projective, bls::G1Projective),
//    proof: VerifyProof
//}

pub struct Coconut<R: RngInstance> {
    parameters: Parameters<R>,
    threshold: u32,
    authorities_total: u32
}


impl<R: RngInstance> Coconut<R> {
    fn new(attributes_size: usize, authorities_threshold: u32, authorities_total: u32) -> Self {
        Self {
            parameters: Parameters::<R>::new(attributes_size),
            threshold: authorities_threshold,
            authorities_total: authorities_total
        }
    }

/*
    pub fn multiparty_keygen(&self) -> (Vec<SecretKey>, Vec<VerifyKey>);

    pub fn aggregate_keys(&self, verify_keys: &Vec<VerifyKey>) -> VerifyKey;

    // This should just be hash to point
    //pub fn compute_commit_hash(attribute_commit: &AttributeCommit) -> bls::G1Projective;

    pub fn prepare_blind_sign(&mut self, shared_attribute_key: &ElGamalPublicKey,
                              attributes: &Vec<Attribute>)
        -> LambdaType;

    pub fn blind_sign(&self, secret_key: &SecretKey, shared_attribute_key: &ElGamalPublicKey,
                      lambda: &LambdaType)
        -> Result<PartialSignature, &'static str>;

    pub fn unblind(&self, private_key: &ElGamalPrivateKey, encrypted_value: &EncryptedValue)
        -> SignatureShare;

    pub fn aggregate(signature_shares: &Vec<SignatureShare>, indexes: &Vec<u64>)
        -> CombinedSignatureShares;

    pub fn make_credential(&mut self, verify_key: &VerifyKey,
                           signature: &Signature, attributes: &Vec<Attribute>) -> Credential;

    pub fn verify_credential(&self, verify_key: &VerifyKey,
                             proven_credential: &Credential) -> bool;
*/
}

//extern crate hex_slice;
//use hex_slice::AsHex;

