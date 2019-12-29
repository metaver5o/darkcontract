pub struct Parameters {
    g1: bls::G1Affine,
    hs: Vec<bls::G1Affine>,
    g2: bls::G2Affine,
}

struct Coconut {
    parameters: Parameters,
    threshold: u32,
    number_authorities: u32
}

// TODO: how to handle rng

type ScalarList = Vec<bls::Scalar>;
type PointList = Vec<bls::G2Projective>;
type VerifyKey = (bls::G2Projective, PointList);
type SecretKey = (bls::Scalar, ScalarList);
type AttributeList = Vec<bls::Scalar>;
type LambdaType = (bls::G1Projective, Vec<EncryptedValue>, SignerProof);
type EncryptedValue = (bls::G1Projective, bls::G1Projective);

type SignerProof = (bls::Scalar, bls::Scalar, Vec<bls::Scalar>, Vec<bls::Scalar>);
type VerifyProof = (bls::Scalar, Vec<bls::Scalar>, bls::Scalar);

struct Credential {
    kappa: bls::G2Projective,
    v: bls::G1Projective,
    sigma_prime: (bls::G1Projective, bls::G1Projective),
    proof: VerifyProof
}

pub fn ttp_keygen(params: &mut Parameters, threshold: usize, number_authorities: usize) 
    -> (Vec<SecretKey>, Vec<VerifyKey>);

pub fn aggregate_keys(params: &Parameters, verify_keys: &Vec<VerifyKey>)
    -> (bls::G2Projective, PointList);

pub fn elgamal_keygen(params: &mut Parameters) -> (bls::Scalar, bls::G1Projective);

pub fn compute_commit_hash(attribute_commit: &bls::G1Projective) -> bls::G1Projective;

pub fn prepare_blind_sign(params: &mut Parameters, gamma: &bls::G1Projective,
                      attributes: &AttributeList) -> LambdaType;

pub fn blind_sign(params: &Parameters, secret_key: &SecretKey,
                  gamma: &bls::G1Projective, lambda: &LambdaType)
    -> Result<PartialSignature, &'static str>;

pub fn unblind(private_key: &bls::Scalar, encrypted_value: &EncryptedValue)
    -> bls::G1Projective;

pub fn aggregate_credential(signature_shares: &Vec<bls::G1Projective>, indexes: &Vec<u64>)
    -> bls::G1Projective;

pub fn prove_credential(params: &mut Parameters, verify_key: &(bls::G2Projective, PointList),
                    signature: &(bls::G1Projective, bls::G1Projective),
                    attributes: &Vec<bls::Scalar>)
    -> (bls::G2Projective, bls::G1Projective,
        (bls::G1Projective, bls::G1Projective), VerifyProof);

pub fn verify_credential(params: &Parameters, verify_key: &(bls::G2Projective, PointList),
                         proven_credential: &(bls::G2Projective, bls::G1Projective,
                                            (bls::G1Projective, bls::G1Projective),
                                            VerifyProof)) -> bool;

