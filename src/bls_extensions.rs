use bls12_381 as bls;
use rand_core::{OsRng, RngCore};

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
                break scalar.unwrap();
            }
        }
    }
}

