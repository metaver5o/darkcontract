use bls12_381 as bls;

pub fn compute_polynomial<'a, I>(coefficients: I, x_primitive: u64)
    -> bls::Scalar
    where I: Iterator<Item=&'a bls::Scalar>
{
    let x = bls::Scalar::from(x_primitive);
    coefficients
        .enumerate()
        .map(|(i, coefficient)| coefficient * x.pow(&[i as u64, 0, 0, 0]))
        .fold(bls::Scalar::zero(), |result, x| result + x)
}

pub fn lagrange_basis<I>(indexes: I)
    -> Vec<bls::Scalar>
where
    I: Iterator<Item=u64> + Clone,
{
    let x = bls::Scalar::zero();
    let mut lagrange_result = Vec::new();

    for i_integer in indexes.clone() {
        let mut numerator = bls::Scalar::one();
        let mut denominator = bls::Scalar::one();

        let i = bls::Scalar::from(i_integer);

        for j_integer in indexes.clone() {
            if j_integer == i_integer {
                continue;
            }

            let j = bls::Scalar::from(j_integer);
            numerator = numerator * (x - j);
            denominator = denominator * (i - j);
        }

        let result = numerator * denominator.invert().unwrap();
        lagrange_result.push(result);
    }

    lagrange_result
}

pub fn lagrange_basis_from_range(range_len: u64) -> Vec<bls::Scalar> {
    lagrange_basis(1..=range_len)
}

