use bls12_381 as bls;

use crate::bls_extensions::*;
use crate::elgamal::*;
use crate::parameters::*;

pub struct SecretKey {
    x: bls::Scalar,
    y: Vec<bls::Scalar>
}

pub struct VerifyKey {
    alpha: bls::G2Projective,
    beta: Vec<bls::G2Projective>
}

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
    params: Parameters<R>,
    threshold: u32,
    authorities_total: u32
}


fn compute_polynomial<'a, I>(coefficients: I, x_primitive: u64)
    -> bls::Scalar
    where I: Iterator<Item=&'a bls::Scalar>
{
    let x = bls::Scalar::from(x_primitive);
    coefficients
        .enumerate()
        .map(|(i, coefficient)| coefficient * x.pow(&[i as u64, 0, 0, 0]))
        .fold(bls::Scalar::zero(), |result, x| result + x)
}

fn lagrange_basis(range_len: u64) -> Vec<bls::Scalar> {
    let x = bls::Scalar::zero();
    let mut lagrange_result = Vec::new();
    for i in 1..=range_len {
        let mut numerator = bls::Scalar::one();
        let mut denominator = bls::Scalar::one();

        for j in 1..=range_len {
            if j == i {
                continue;
            }
            numerator = numerator * (x - bls::Scalar::from(j));
            denominator = denominator * (bls::Scalar::from(i) - bls::Scalar::from(j));
        }

        let result = numerator * denominator.invert().unwrap();
        lagrange_result.push(result);
    }
    lagrange_result
}

fn ec_sum(points: &Vec<bls::G2Projective>) -> bls::G2Projective {
    points.iter()
        .fold(bls::G2Projective::identity(), |result, x| result + *x)
}
pub trait GeneratorPoint {
    fn get_identity() -> Self;
    fn add(&self, rhs: &Self) -> Self;
}

impl GeneratorPoint for bls::G1Projective {
    fn get_identity() -> Self {
        Self::identity()
    }

    fn add(&self, rhs: &Self) -> Self {
        self + rhs
    }
}

impl GeneratorPoint for bls::G2Projective {
    fn get_identity() -> Self {
        Self::identity()
    }

    fn add(&self, rhs: &Self) -> Self {
        self + rhs
    }
}

fn ecc_sum<G: GeneratorPoint + Sized>(points: &Vec<G>) -> G {
    points.iter()
        .fold(G::get_identity(), |result, x| result.add(x))
}


impl<R: RngInstance> Coconut<R> {
    pub fn new(attributes_size: usize, authorities_threshold: u32, authorities_total: u32) -> Self {
        Self {
            params: Parameters::<R>::new(attributes_size),
            threshold: authorities_threshold,
            authorities_total: authorities_total
        }
    }

    pub fn multiparty_keygen(&self) -> (Vec<SecretKey>, Vec<VerifyKey>) {
        let attributes_size = self.params.hs.len();
        assert!(self.authorities_total >= self.threshold);
        assert!(attributes_size > 0);

        let n_random_scalars = |n| {
            (0..n).map(|_| self.params.random_scalar()).collect()
        };
        let v_poly: Vec<_> = n_random_scalars(self.threshold);
        let w_poly: Vec<Vec<_>> = (0..attributes_size).map(|_| n_random_scalars(self.threshold)).collect();

        //// Generate shares
        let x_shares = (1..=self.authorities_total).map(
            |i| compute_polynomial(v_poly.iter(), i as u64));
        let y_shares = (1..=self.authorities_total).map(
            |i|
                w_poly.iter()
                    .map(
                        move |w_coefficients|
                        compute_polynomial(w_coefficients.iter(), i as u64)
                    )
            );

        // Set the keys
        // sk_i = (x, (y_1, y_2, ..., y_q))
        // vk_i = (g2^x, (g2^y_1, g2^y_2, ..., g2^y_q)) = (a, (B_1, B_2, ..., B_q))
        let verify_keys: Vec<VerifyKey> =
            x_shares.clone().zip(y_shares.clone())
                .map(
                    |(x, y_share_parts)| 
                    VerifyKey {
                        alpha: self.params.g2 * x,
                        beta: 
                            y_share_parts
                                .map(|y| self.params.g2 * y)
                                .collect()
                    }
                )
                .collect();
        // We are moving out of x_shares into SecretKey, so this line happens
        // after creating verify_keys to avoid triggering borrow checker.
        let secret_keys: Vec<SecretKey> =
            x_shares.zip(y_shares)
                .map(
                    |(x, y)|
                    SecretKey{
                        x: x,
                        y: y.collect()
                    }
                )
                .collect();

        (secret_keys, verify_keys)
    }

    pub fn aggregate_keys(&self, verify_keys: &Vec<VerifyKey>) -> VerifyKey {
        let lagrange = lagrange_basis(verify_keys.len() as u64);

        let (alpha, beta): (Vec<&_>, Vec<&Vec<_>>) =
            verify_keys.iter().map(|ref key| (&key.alpha, &key.beta)).unzip();

        assert!(beta.len() > 0);
        let attributes_size = beta[0].len();

        assert_eq!(lagrange.len(), alpha.len());

        let aggregate_alpha = ec_sum(
            &alpha.iter().zip(lagrange.iter())
                .map(
                    |(a, l)|
                    *a * l
                )
                .collect());
        let aggregate_beta: Vec<_> = (0..attributes_size).map(|i| ec_sum(
            &beta.iter().zip(lagrange.iter())
                .map(
                    |(b, l)|
                    b[i] * l
                )
                .collect()
            )
        ).collect();

        return VerifyKey {
            alpha: aggregate_alpha,
            beta: aggregate_beta
        }
    }

/*
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

#[test]
fn test_multiparty_keygen() {
    let attributes_size = 2;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let sigs_x: Vec<bls::G1Projective> = secret_keys.iter()
        .map(|secret_key| coconut.params.g1 * secret_key.x)
        .collect();
    let l = lagrange_basis(6);
    let sig = ecc_sum(&l.iter().zip(sigs_x.iter()).map(|(l_i, s_i)| s_i * l_i).collect());

    let ppair_1 = bls::pairing(&bls::G1Affine::from(sig), &coconut.params.g2);
    let ppair_2 = bls::pairing(&coconut.params.g1, &bls::G2Affine::from(verify_key.alpha));
    assert_eq!(ppair_1, ppair_2);
}

