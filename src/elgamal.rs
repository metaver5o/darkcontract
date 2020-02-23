use bls12_381 as bls;

use crate::bls_extensions::*;
use crate::parameters::*;

pub type EncryptedValue = (bls::G1Projective, bls::G1Projective);

pub struct ElGamalPrivateKey<'a, R: RngInstance> {
    params: &'a Parameters<R>,
    pub private_key: bls::Scalar,
}

pub struct ElGamalPublicKey<'a, R: RngInstance> {
    pub params: &'a Parameters<R>,
    pub public_key: bls::G1Projective,
}

impl<'a, R: RngInstance> ElGamalPrivateKey<'a, R> {
    pub fn new(params: &'a Parameters<R>) -> Self {
        Self {
            params: params,
            private_key: params.random_scalar(),
        }
    }

    pub fn to_public(&self) -> ElGamalPublicKey<'a, R> {
        ElGamalPublicKey {
            params: self.params,
            public_key: self.params.g1 * self.private_key,
        }
    }

    pub fn decrypt(&self, ciphertext: &EncryptedValue) -> bls::G1Projective {
        let (a, b) = ciphertext;
        b - a * self.private_key
    }
}

impl<'a, R: RngInstance> ElGamalPublicKey<'a, R> {
    pub fn encrypt(
        &self,
        attribute: &bls::Scalar,
        attribute_key: &bls::Scalar,
        shared_value: &bls::G1Projective,
    ) -> EncryptedValue {
        (
            self.params.g1 * attribute_key,
            self.public_key * attribute_key + shared_value * attribute,
        )
    }
}
