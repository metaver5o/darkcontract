extern crate darktoken;
use crate::darktoken::RandomScalar;
use bls12_381 as bls;

struct CoconutSettings {
    attributes: u32,
    threshold: u32,
    total: u32,
}

struct Authority {
    index: u64,
    secret_key: darktoken::SecretKey,
    coconut: darktoken::Coconut<darktoken::OsRngInstance>,
}

impl Authority {
    fn new(index: u64, secret_key: darktoken::SecretKey, settings: &CoconutSettings) -> Self {
        Self {
            index,
            secret_key,

            coconut: darktoken::Coconut::<darktoken::OsRngInstance>::new(
                settings.attributes,
                settings.threshold,
                settings.total,
            ),
        }
    }

    fn blind_sign<'a>(
        &self,
        sign_request: &darktoken::BlindSignatureRequest,
        public_key: &darktoken::ElGamalPublicKey<'a, darktoken::OsRngInstance>,
        public_attributes: &Vec<bls::Scalar>,
        external_commitments: Vec<Box<dyn darktoken::ProofCommitments>>,
    ) -> darktoken::PartialSignature {
        sign_request
            .blind_sign(
                &self.coconut.params,
                &self.secret_key,
                &public_key,
                &public_attributes,
                external_commitments,
            )
            .unwrap()
    }
}

fn generate_keys(settings: &CoconutSettings) -> (Vec<darktoken::SecretKey>, darktoken::VerifyKey) {
    let coconut = darktoken::Coconut::<darktoken::OsRngInstance>::new(
        settings.attributes,
        settings.threshold,
        settings.total,
    );

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    (secret_keys, verify_key)
}

struct Token<'a> {
    value: u64,
    serial: bls::Scalar,
    signature: darktoken::Signature,
    private_key: darktoken::ElGamalPrivateKey<'a, darktoken::OsRngInstance>,
}

struct Wallet {
    coconut: darktoken::Coconut<darktoken::OsRngInstance>,
}

impl Wallet {
    fn new(settings: &CoconutSettings) -> Self {
        Self {
            coconut: darktoken::Coconut::<darktoken::OsRngInstance>::new(
                settings.attributes,
                settings.threshold,
                settings.total,
            ),
        }
    }

    fn deposit(&self, value: u64, authorities: &Vec<Authority>) -> Token {
        // Assuming we can deposit the money
        let private_attributes = vec![self.coconut.params.random_scalar()];
        let public_attributes = vec![bls::Scalar::from(value)];

        let private_key = darktoken::ElGamalPrivateKey::new(&self.coconut.params);
        let public_key = private_key.to_public();

        let sign_request = self.coconut.make_blind_sign_request(
            &public_key,
            &private_attributes,
            &public_attributes,
            Vec::new(),
        );

        let mut indexed_shares: Vec<_> = authorities
            .iter()
            .map(|authority| {
                (
                    authority.index,
                    authority
                        .blind_sign(&sign_request, &public_key, &public_attributes, Vec::new())
                        .unblind(&private_key),
                )
            })
            .collect();

        // Lets remove 2 of them since this is 5 of 7
        // For testing purposes...
        indexed_shares.remove(0);
        indexed_shares.remove(4);

        let (indexes, shares): (Vec<_>, Vec<_>) = indexed_shares.into_iter().unzip();

        let commit_hash = sign_request.compute_commit_hash();
        let signature = darktoken::Signature {
            commit_hash,
            sigma: self.coconut.aggregate(&shares, indexes),
        };

        Token {
            value,
            serial: private_attributes[0],
            signature,
            private_key,
        }
    }
}

fn main() {
    let settings = CoconutSettings {
        attributes: 2,

        threshold: 5,
        total: 7,
    };
    let (secret_keys, verify_key) = generate_keys(&settings);

    let authorities: Vec<_> = (0..settings.total)
        .zip(secret_keys.into_iter())
        .map(|(i, secret_key)| Authority::new(i as u64, secret_key, &settings))
        .collect();

    let mut wallet = Wallet::new(&settings);
    let token = wallet.deposit(110, &authorities);
}
