use bls12_381 as bls;

use crate::bls_extensions::*;

pub struct Parameters<R: RngInstance> {
    g1: bls::G1Affine,
    hs: Vec<bls::G1Affine>,
    g2: bls::G2Affine,
    _marker: std::marker::PhantomData<R>
}

impl<R: RngInstance> Parameters<R> {
    pub fn new(attributes_size: usize) -> Self {
        let g1 = bls::G1Affine::generator();
        let g2 = bls::G2Affine::generator();

        let hs = (0..attributes_size).map(
            |i| {
                let message = format!("h{}", i);
                bls::G1Affine::hash_to_point(message.as_bytes())
            }).collect();

        Parameters {
            g1: g1,
            hs: hs,
            g2: g2,
            _marker: std::marker::PhantomData
        }
    }

    pub fn random_scalar(&self) -> bls::Scalar {
        bls::Scalar::new_random::<R>()
    }
}

/*

pub struct Coconut<R: RngInstance> {
    parameters: Parameters<R>,
    threshold: u32,
    number_authorities: u32
}

trait RngInstance {
    fn random_number() -> u32;
}

struct ThreadRng;

impl RngInstance for ThreadRng {
    fn random_number() -> u32 {
        thread_rng().gen()
    }
}

// TODO: how to handle rng

type ScalarList = Vec<bls::Scalar>;
type PointList = Vec<bls::G2Projective>;
type VerifyKey = (bls::G2Projective, PointList);
type SecretKey = (bls::Scalar, ScalarList);
type Attribute = bls::Scalar;
type LambdaType = (bls::G1Projective, Vec<EncryptedValue>, SignerProof);

type SignerProof = (bls::Scalar, bls::Scalar, Vec<bls::Scalar>, Vec<bls::Scalar>);
type VerifyProof = (bls::Scalar, Vec<bls::Scalar>, bls::Scalar);

type SignatureShare = bls::G1Projective;
type CombinedSignatureShares = bls::G1Projective;
type Signature = (bls::G1Projective, bls::G1Projective);

struct Credential {
    kappa: bls::G2Projective,
    v: bls::G1Projective,
    sigma_prime: (bls::G1Projective, bls::G1Projective),
    proof: VerifyProof
}

impl<R: RngInstance> Coconut<R> {
    fn new(attributes_size: usize, authorities_threshold: u32, authorities_total: u32) -> Self {
        Self {
            _marker: std::marker::PhantomData
        }
    }

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
}

// ElGamal

type EncryptedValue = (bls::G1Projective, bls::G1Projective);

struct ElGamalPrivateKey {
    params: &Parameters,
    private_key: bls::Scalar
}

struct ElGamalPublicKey {
    params: &Parameters,
    public_key: bls::G1Projective
}

impl ElGamalPrivateKey {
    fn new(params: &mut Parameters) -> Self;

    fn to_public(&self) -> ElGamalPublicKey;

    fn decrypt(&self, ciphertext: &EncryptedValue) -> bls::G1Projective;
}

impl ElGamalPublicKey {
    fn encrypt(&self, attribute: &bls::Scalar, attribute_key: &bls::Scalar,
               shared_value: &bls::G1Projective) -> EncryptedValue;
}

*/

extern crate hex_slice;
use hex_slice::AsHex;

#[test]
fn test_parameters() {
    let attrs_size = 2;
    let params = Parameters::<OsRngInstance>::new(attrs_size);

    assert_eq!(
        params.g1,
        bls::G1Affine::from_compressed(&[
            0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c,
            0x4f, 0xa9, 0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
            0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f,
            0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb
        ]).unwrap()
    );

    assert_eq!(
        params.g2,
        bls::G2Affine::from_compressed(&[
            0x93, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0,
            0x88, 0x27, 0x4f, 0x65, 0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a,
            0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49, 0x33, 0x4c, 0xf1, 0x12,
            0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
            0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91, 0x26, 0x08, 0x05, 0x27,
            0x2d, 0xc5, 0x10, 0x51, 0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02,
            0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77, 0x0b, 0xac, 0x03, 0x26,
            0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8
        ]).unwrap()
    );

    assert_eq!(params.hs.len(), 2);

    assert_eq!(
        params.hs[0],
        bls::G1Affine::from_compressed(&[
            0x8e, 0x0f, 0xec, 0x87, 0x77, 0x55, 0x0a, 0x45, 0x55, 0xde, 0x4f, 0x32,
            0xaa, 0x1c, 0x67, 0xac, 0x8e, 0x72, 0x36, 0x37, 0x21, 0x8b, 0x88, 0xf1,
            0x1d, 0x5e, 0x44, 0xb3, 0x4b, 0xc7, 0x5e, 0x60, 0xdc, 0x97, 0xca, 0x1f,
            0xf7, 0x88, 0xef, 0xe6, 0x82, 0x8a, 0x35, 0x6f, 0x75, 0x51, 0xe5, 0xb5
        ]).unwrap()
    );

    assert_eq!(
        params.hs[1],
        bls::G1Affine::from_compressed(&[
            0xb8, 0x7d, 0xcc, 0x74, 0xf4, 0xdb, 0x36, 0x03, 0x02, 0x92, 0x1f, 0xd8,
            0x06, 0x25, 0xd0, 0xdd, 0xef, 0x94, 0x32, 0xf5, 0xef, 0x98, 0xde, 0xf8,
            0x0f, 0x4a, 0xce, 0xfd, 0xfb, 0x37, 0x27, 0xaf, 0xce, 0x97, 0xb3, 0x63,
            0x98, 0xc2, 0xe6, 0x04, 0x6f, 0x42, 0x0e, 0x17, 0x7a, 0x5e, 0xa7, 0x82
        ]).unwrap()
    );
}

