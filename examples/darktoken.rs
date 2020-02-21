extern crate darktoken;
use std::path::Path;
use bls12_381 as bls;
use clap::{Arg, App, SubCommand};
use crate::darktoken::RandomScalar;

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

struct Wallet<'a> {
    coconut: darktoken::Coconut<darktoken::OsRngInstance>,
    verify_key: &'a darktoken::VerifyKey,
}

struct WithdrawRequest {
    burn_value: bls::G1Projective,
    burn_proof: BurnProof,
    credential: darktoken::Credential,
}

impl<'a> Wallet<'a> {
    fn new(settings: &CoconutSettings, verify_key: &'a darktoken::VerifyKey) -> Self {
        Self {
            coconut: darktoken::Coconut::<darktoken::OsRngInstance>::new(
                settings.attributes,
                settings.threshold,
                settings.total,
            ),
            verify_key,
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

    fn withdraw(&self, token: Token) -> WithdrawRequest {
        let burn_value = self.coconut.params.g1 * token.serial;

        let proof_builder = BurnProofBuilder::new(&self.coconut.params, &token.serial);
        let commitments = proof_builder.commitments();

        let private_attributes = vec![token.serial, bls::Scalar::from(token.value)];

        let credential = self.coconut.make_credential(
            self.verify_key,
            &token.signature,
            &private_attributes,
            vec![commitments],
        );

        assert!(credential.verify(
            &self.coconut.params,
            &self.verify_key,
            &Vec::new(),
            vec![proof_builder.commitments()],
        ));

        let burn_proof = proof_builder.finish(&credential.challenge);

        WithdrawRequest {
            burn_value,
            burn_proof,
            credential,
        }
    }

    fn token_commit(&self, value: u64, blind: &bls::Scalar) -> bls::G1Projective {
        assert!(self.coconut.params.hs.len() >= 1);

        self.coconut.params.g1 * bls::Scalar::from(value) + self.coconut.params.hs[0] * blind
    }

    fn split(
        &self,
        token: Token,
        value1: u64,
        value2: u64,
        authorities: &Vec<Authority>,
    ) -> Result<(Token, Token), &'static str> {
        assert_eq!(token.value, value1 + value2);

        let burn_value = self.coconut.params.g1 * token.serial;

        let blind1 = self.coconut.params.random_scalar();
        let blind2 = self.coconut.params.random_scalar();
        let blind = blind1 + blind2;

        let commit = self.token_commit(token.value, &blind);
        let commit1 = self.token_commit(value1, &blind1);
        let commit2 = self.token_commit(value2, &blind2);

        assert_eq!(commit, commit1 + commit2);

        /*
        let commit_proof_builder = CommitProofBuilder::new(
            &self.coconut.params,
            &bls::Scalar::from(token.value),
            &blind,
        );
        let commit1_proof_builder = CommitProofBuilder::new(
            &self.coconut.params,
            &bls::Scalar::from(value1),
            &blind1,
        );
        let commit2_proof_builder = CommitProofBuilder::new(
            &self.coconut.params,
            &bls::Scalar::from(value2),
            &blind2,
        );

        let commit_commitments = commit_proof_builder.commitments();
        let commit1_commitments = commit1_proof_builder.commitments();
        let commit2_commitments = commit2_proof_builder.commitments();
        */

        // TODO: do we have a separate challenge for ProveCred() and each PrepBlindSign() call?

        // Burn a coin ... This code is nearly identical to withdraw()
        let proof_builder = BurnProofBuilder::new(&self.coconut.params, &token.serial);
        let commitments = proof_builder.commitments();

        let private_attributes = vec![token.serial, bls::Scalar::from(token.value)];

        let credential = self.coconut.make_credential(
            self.verify_key,
            &token.signature,
            &private_attributes,
            //vec![commitments, commit_commitments, commit1_commitments, commit2_commitments],
            vec![commitments],
        );

        let burn_proof = proof_builder.finish(&credential.challenge);
        //let commit_proof = commit_proof_builder.finish(&credential.challenge);
        //let commit1_proof = commit1_proof_builder.finish(&credential.challenge);
        //let commit2_proof = commit2_proof_builder.finish(&credential.challenge);

        // Mint a coin ... Code is nearly identical to deposit()
        // these functions call BlindSign()
        let token1 = self.deposit(value1, authorities);
        let token2 = self.deposit(value2, authorities);

        // Now authorities process the tokens
        // TODO: spent burns list contains burn_value
        if commit != commit1 + commit2 {
            return Err("commits don't add up");
        }
        // pretty similar to process_withdraw()
        let burn_commitments =
            burn_proof.commitments(&self.coconut.params, &credential.challenge, &burn_value);
        if !credential.verify(
            &self.coconut.params,
            &self.verify_key,
            &Vec::new(),
            vec![burn_commitments],
        ) {
            return Err("verify failed");
        }

        // Unblind token1, token2 and aggregate (already done in call to deposit())
        Ok((token1, token2))
    }
}

struct BurnProofBuilder<'a, R: darktoken::RngInstance> {
    params: &'a darktoken::Parameters<R>,

    // Secrets
    serial: &'a bls::Scalar,

    witness: bls::Scalar,
}

struct BurnProofCommitments<'a, R: darktoken::RngInstance> {
    params: &'a darktoken::Parameters<R>,

    // Commitments
    commit: bls::G1Projective,
}

struct BurnProof {
    response: bls::Scalar,
}

impl<'a, R: darktoken::RngInstance> BurnProofBuilder<'a, R> {
    fn new(params: &'a darktoken::Parameters<R>, serial: &'a bls::Scalar) -> Self {
        Self {
            params,
            serial,
            witness: params.random_scalar(),
        }
    }

    fn commitments(&self) -> Box<dyn darktoken::ProofCommitments + 'a> {
        Box::new(BurnProofCommitments {
            params: self.params,
            commit: self.params.g1 * self.witness,
        })
    }

    fn finish(&self, challenge: &bls::Scalar) -> BurnProof {
        BurnProof {
            response: self.witness - challenge * self.serial,
        }
    }
}

impl<'a, R: darktoken::RngInstance> darktoken::ProofCommitments for BurnProofCommitments<'a, R> {
    fn commit(&self, hasher: &mut darktoken::ProofHasher) {
        hasher.add_g1_affine(&self.params.g1);
        hasher.add_g1(&self.commit);
    }
}

impl BurnProof {
    fn commitments<'a, R: darktoken::RngInstance>(
        &self,
        params: &'a darktoken::Parameters<R>,
        challenge: &bls::Scalar,
        burn_value: &bls::G1Projective,
    ) -> Box<dyn darktoken::ProofCommitments + 'a> {
        Box::new(BurnProofCommitments {
            params,
            commit: burn_value * challenge + params.g1 * self.response,
        })
    }
}
struct CommitProofBuilder<'a, R: darktoken::RngInstance> {
    params: &'a darktoken::Parameters<R>,

    // Secrets
    value: &'a bls::Scalar,
    blind: &'a bls::Scalar,

    witness_value: bls::Scalar,
    witness_blind: bls::Scalar,
}

struct CommitProofCommitments<'a, R: darktoken::RngInstance> {
    params: &'a darktoken::Parameters<R>,

    // Commitments
    commit: bls::G1Projective,
}

struct CommitProof {
    response_value: bls::Scalar,
    response_blind: bls::Scalar,
}

impl<'a, R: darktoken::RngInstance> CommitProofBuilder<'a, R> {
    fn new(
        params: &'a darktoken::Parameters<R>,
        value: &'a bls::Scalar,
        blind: &'a bls::Scalar,
    ) -> Self {
        Self {
            params,
            value,
            blind,
            witness_value: params.random_scalar(),
            witness_blind: params.random_scalar(),
        }
    }

    fn commitments(&self) -> Box<dyn darktoken::ProofCommitments + 'a> {
        assert!(self.params.hs.len() > 0);
        let h1 = self.params.hs[0];

        Box::new(CommitProofCommitments {
            params: self.params,
            commit: self.params.g1 * self.witness_value + h1 * self.witness_blind,
        })
    }

    fn finish(&self, challenge: &bls::Scalar) -> CommitProof {
        CommitProof {
            response_value: self.witness_value - challenge * self.value,
            response_blind: self.witness_blind - challenge * self.blind,
        }
    }
}

impl<'a, R: darktoken::RngInstance> darktoken::ProofCommitments for CommitProofCommitments<'a, R> {
    fn commit(&self, hasher: &mut darktoken::ProofHasher) {
        hasher.add_g1_affine(&self.params.g1);
        assert!(self.params.hs.len() > 0);
        let h1 = self.params.hs[0];
        hasher.add_g1_affine(&h1);
        hasher.add_g1(&self.commit);
    }
}

impl CommitProof {
    fn commitments<'a, R: darktoken::RngInstance>(
        &self,
        params: &'a darktoken::Parameters<R>,
        challenge: &bls::Scalar,
        token_commit: &bls::G1Projective,
    ) -> Box<dyn darktoken::ProofCommitments + 'a> {
        assert!(params.hs.len() > 0);
        let h1 = params.hs[0];

        Box::new(CommitProofCommitments {
            params,
            commit: token_commit * challenge
                + params.g1 * self.response_value
                + h1 * self.response_blind,
        })
    }
}

struct Bank<'a> {
    coconut: darktoken::Coconut<darktoken::OsRngInstance>,
    verify_key: &'a darktoken::VerifyKey,
    spent_burns: Vec<bls::G1Projective>,
}

impl<'a> Bank<'a> {
    fn new(settings: &CoconutSettings, verify_key: &'a darktoken::VerifyKey) -> Self {
        Self {
            coconut: darktoken::Coconut::<darktoken::OsRngInstance>::new(
                settings.attributes,
                settings.threshold,
                settings.total,
            ),
            verify_key,
            spent_burns: Vec::new(),
        }
    }

    fn process_withdraw(&mut self, withdraw: WithdrawRequest) -> bool {
        if self.spent_burns.contains(&withdraw.burn_value) {
            return false;
        }
        // To avoid double spends of the same coin
        self.spent_burns.push(withdraw.burn_value);

        let burn_commits = withdraw.burn_proof.commitments(
            &self.coconut.params,
            &withdraw.credential.challenge,
            &withdraw.burn_value,
        );

        withdraw.credential.verify(
            &self.coconut.params,
            &self.verify_key,
            &Vec::new(),
            vec![burn_commits],
        )
    }
}

fn main() {
    let matches = App::new("darktoken")
        .version("0.1.0")
        .author("Amir Taaki <amir@dyne.org>")
        .about("Issue and manage dark tokens")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .takes_value(true)
            .value_name("CONFIG_DIR")
            .help("Config directory"))
        .arg(Arg::with_name("num")
            .short("n")
            .long("number")
            .takes_value(true)
            .value_name("NUMBER")
            .help("Five less than favnumb"))
        .subcommand(SubCommand::with_name("init")
            .about("Initialize"))
        .subcommand(SubCommand::with_name("deposit")
            .about("Deposit money")
            .arg(Arg::with_name("value")
                .required(true)
                .value_name("VALUE")
                .help("amount to deposit")))
        .get_matches();

    let default_dir = dirs::home_dir().unwrap().as_path().join(".darktoken/");

    let config_dir = match matches.value_of("config") {
        None => default_dir.as_path(),
        Some(path_str) => Path::new(path_str)
    };

    if !config_dir.exists() {
        let _ = std::fs::create_dir(config_dir);
        println!("Initialized new config directory: {}", config_dir.display());
    }

    match matches.subcommand() {
        ("init",    Some(matches)) => {
        },
        ("deposit", Some(matches)) => {
            //let matches = matches.
            let value = matches.value_of("value").unwrap().parse::<i32>().unwrap();
            println!("Deposit: {:?}", value);
        },
        _ => {
            eprintln!("Invalid subcommand invoked");
            return;
        }
    }

    if let(Some(matches)) = matches.subcommand_matches("deposit") {
    }
    return;

    let settings = CoconutSettings {
        attributes: 2,

        threshold: 5,
        total: 7,
    };
    let (secret_keys, verify_key) = generate_keys(&settings);

    let authorities: Vec<_> = (0..settings.total)
        .zip(secret_keys.into_iter())
        .map(|(i, secret_key)| Authority::new((i + 1) as u64, secret_key, &settings))
        .collect();

    // Normally the authorities, bank and wallet have some form of network protocol
    // between themselves.
    let mut bank = Bank::new(&settings, &verify_key);

    let wallet = Wallet::new(&settings, &verify_key);
    let coin_value = 110;
    let token = wallet.deposit(coin_value, &authorities);

    let withdraw_request = wallet.withdraw(token);

    // Now we serialize withdraw_request ...
    // ... Send it to the guy holding the money
    // ... They validate the request. If it works, they process our payout.

    let withdraw_success = bank.process_withdraw(withdraw_request);
    assert_eq!(withdraw_success, true);
    println!("Successfully withdrew our token of {} $", coin_value);

    // Lets now make a new coin and split it
    let token = wallet.deposit(coin_value, &authorities);
    match wallet.split(token, 100, 10, &authorities) {
        Err(err) => eprintln!("error: split failed: {}", err),
        Ok((token1, token2)) => println!("split worked."),
    }
}
