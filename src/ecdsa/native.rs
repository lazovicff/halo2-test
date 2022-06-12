use halo2_proofs::arithmetic::{CurveAffine, BaseExt, Field, FieldExt};
use group::prime::PrimeCurveAffine;
use group::Curve;
use group::ff::PrimeField;
use rand::thread_rng;
use std::io::Error;

#[derive(Default, Clone, Copy)]
pub struct SigData<F: FieldExt> {
	pub r: F,
	pub s: F,
}

impl<F: FieldExt> SigData<F> {
	pub fn from_repr(r: F::Repr, s: F::Repr) -> Self {
		let r = F::from_repr(r).unwrap();
		let s = F::from_repr(s).unwrap();

		Self { r, s }
	}
}

pub fn generate_signature<E: CurveAffine>(sk: E::ScalarExt, m_hash: E::ScalarExt) -> Result<(SigData<E::ScalarExt>, E), Error> {
	let mut rng = thread_rng();

	// generate a valid signature
	let generator = <E as PrimeCurveAffine>::generator();
	let pk = generator * sk;
	let pk: E = pk.to_affine();

	let randomness = <E as CurveAffine>::ScalarExt::random(&mut rng);
	let randomness_inv = randomness.invert().unwrap();
	let sig_point = generator * randomness;
	let x = sig_point.to_affine().coordinates().unwrap().x().clone();

	let x_repr = &mut Vec::with_capacity(32);
	x.write(x_repr)?;

	let mut x_bytes = [0u8; 64];
	x_bytes[..32].copy_from_slice(&x_repr[..]);

	let x_bytes_on_n = <E as CurveAffine>::ScalarExt::from_bytes_wide(&x_bytes); // get x cordinate (E::Base) on E::Scalar
	let sig_s = randomness_inv * (m_hash + x_bytes_on_n * sk);

	let sig_data = SigData {
		r: x_bytes_on_n,
		s: sig_s,
	};
	Ok((sig_data, pk))
}