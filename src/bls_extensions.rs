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

// Hash a message using Sha512, and then return the first N bytes
// used to map to a curve point.
macro_rules! make_hash {
    ($message:ident, $i:ident, $array_size:literal) => {{
        let mut hash_data = [0u8; $array_size];

        let i_data = $i.to_le_bytes();

        const HASH_SIZE: usize = 64;
        let mut j = 0;
        while j * HASH_SIZE < $array_size {
            let j_data = j.to_le_bytes();

            let mut hasher = Sha512::new();
            hasher.input($message);
            hasher.input(&i_data);
            hasher.input(&j_data);
            let hash_result = hasher.result();

            let start = j * HASH_SIZE;
            let end =
                if start + HASH_SIZE > $array_size {
                    $array_size
                } else {
                    start + HASH_SIZE
                };
            hash_data.copy_from_slice(&hash_result[start..end]);

            j += 1;
        }

        hash_data
    }}
}

pub trait HashableGenerator {
    fn hash_to_point(message: &[u8]) -> Self;
}

// Extend G1 point with a hash_to_point() method.
impl HashableGenerator for bls::G1Affine {
    fn hash_to_point(message: &[u8]) -> Self {
        for i in 0u32 .. {
            let hash = make_hash!(message, i, 48);

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

// ec_sum function, define a trait so we can generically sum ec points
// Unfortunately library doesn't implement a shared trait for G1 and G2

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

pub fn ec_sum<G: GeneratorPoint + Sized>(points: &Vec<G>) -> G {
    points.iter()
        .fold(G::get_identity(), |result, x| result.add(x))
}

