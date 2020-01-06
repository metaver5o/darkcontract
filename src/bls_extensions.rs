use bls12_381 as bls;
use sha2::{Sha512, Digest};
use rand_core::{RngCore, OsRng};

// This code provides the ability to create a random scalar using a trait
pub trait RngInstance {
    fn fill_bytes(dest: &mut [u8]);
}

pub struct OsRngInstance;

impl RngInstance for OsRngInstance {
    fn fill_bytes(dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }
}

pub trait RandomScalar {
    fn new_random<R: RngInstance>() -> Self;
}

// Extend bls::Scalar with a new_random() method.
impl RandomScalar for bls::Scalar {
    fn new_random<R: RngInstance>() -> Self {
        loop {
            let mut random_bytes = [0u8; 32];
            R::fill_bytes(&mut random_bytes);
            let scalar = bls::Scalar::from_bytes(&random_bytes);
            if scalar.is_some().unwrap_u8() == 1 {
                break scalar.unwrap()
            }
        }
    }
}

// Hash a message using Sha512, and then return the first 48 bytes
// used to map to a curve point.
fn sha512_hash(message: &[u8]) -> [u8; 48] {
    let mut hasher = Sha512::new();
    hasher.input(message);
    let hash_result = hasher.result();
    assert_eq!(hash_result.len(), 64);

    let mut hash_data = [0u8; 48];
    hash_data.copy_from_slice(&hash_result[0..48]);
    //println!("{:x}", hash_data.as_hex());
    hash_data
}

pub trait HashableGenerator {
    fn hash_to_point(message: &[u8]) -> Self;
}

// Extend G1 point with a hash_to_point() method.
impl HashableGenerator for bls::G1Affine {
    fn hash_to_point(message: &[u8]) -> Self {
        for i in 0u32 .. {
            let i_data = i.to_le_bytes();

            let mut data = Vec::with_capacity(message.len() + i_data.len());
            data.extend_from_slice(message);
            data.extend_from_slice(&i_data);

            let hash = sha512_hash(data.as_slice());

            let point = {
                let point_optional = Self::from_compressed_unchecked(&hash);
                if point_optional.is_none().unwrap_u8() == 1 {
                    continue;
                }
                let affine_point = point_optional.unwrap();
                let projective_point = bls::G1Projective::from(affine_point).clear_cofactor();
                Self::from(projective_point)
            };

            assert_eq!(bool::from(point.is_on_curve()), true);
            assert_eq!(bool::from(point.is_torsion_free()), true);

            return point;
        }
        unreachable!();
    }
}

// Add conversions for the projective version of G1
impl HashableGenerator for bls::G1Projective {
    fn hash_to_point(message: &[u8]) -> Self {
        bls::G1Projective::from(bls::G1Affine::hash_to_point(&message))
    }
}

