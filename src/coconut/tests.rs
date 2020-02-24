#[allow(unused_imports)]
use bls12_381 as bls;
#[allow(unused_imports)]
use itertools::izip;

#[allow(unused_imports)]
use crate::bls_extensions::*;
#[allow(unused_imports)]
use crate::coconut::coconut::*;
#[allow(unused_imports)]
use crate::elgamal::*;
#[allow(unused_imports)]
use crate::utility::*;

#[test]
fn test_multiparty_keygen() {
    let attributes_size = 2;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let sigs_x: Vec<bls::G1Projective> = secret_keys
        .iter()
        .map(|secret_key| coconut.params.g1 * secret_key.x)
        .collect();
    let l = lagrange_basis_from_range(6);

    let mut sig = bls::G1Projective::identity();
    for (s_i, l_i) in izip!(&sigs_x, &l) {
        sig += s_i * l_i;
    }

    let ppair_1 = bls::pairing(&bls::G1Affine::from(sig), &coconut.params.g2);
    let ppair_2 = bls::pairing(&coconut.params.g1, &bls::G2Affine::from(verify_key.alpha));
    assert_eq!(ppair_1, ppair_2);
}

#[test]
fn test_multiparty_coconut() {
    let attributes_size = 3;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let d = ElGamalPrivateKey::new(&coconut.params);
    let gamma = d.to_public(&coconut.params);

    //let private_attributes = vec![bls::Scalar::from(110), bls::Scalar::from(4)];
    //let public_attributes = vec![bls::Scalar::from(256)];
    let private_attributes = vec![bls::Scalar::from(110)];
    let public_attributes = vec![bls::Scalar::from(4), bls::Scalar::from(256)];

    let sign_request = coconut.make_blind_sign_request(
        &gamma,
        &private_attributes,
        &public_attributes,
    );

    let blind_signatures: Vec<_> = secret_keys
        .iter()
        .map(|secret_key| {
            sign_request
                .blind_sign(
                    &coconut.params,
                    secret_key,
                    &gamma,
                    &public_attributes,
                )
                .unwrap()
        })
        .collect();

    // Signatures should be a struct, with an authority ID inside them
    let mut signature_shares: Vec<_> = blind_signatures
        .iter()
        .map(|blind_signature| blind_signature.unblind(&d))
        .collect();
    let mut indexes: Vec<u64> = (1u64..=signature_shares.len() as u64).collect();

    signature_shares.remove(0);
    indexes.remove(0);
    signature_shares.remove(4);
    indexes.remove(4);

    let commit_hash = sign_request.compute_commit_hash();
    let signature = Signature {
        commit_hash,
        sigma: coconut.aggregate(&signature_shares, indexes),
    };

    //let private_attributes2 = vec![bls::Scalar::from(110)];
    //let public_attributes2 = vec![bls::Scalar::from(4), bls::Scalar::from(256)];
    let private_attributes2 = vec![bls::Scalar::from(110), bls::Scalar::from(4)];
    let public_attributes2 = vec![bls::Scalar::from(256)];

    let credential =
        coconut.make_credential(&verify_key, &signature, &private_attributes2);

    let is_verify = credential.verify(
        &coconut.params,
        &verify_key,
        &public_attributes2,
    );
    assert!(is_verify);
}
