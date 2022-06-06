use halo2_proofs::arithmetic::{CurveAffine, FieldExt, BaseExt, Field};
use group::prime::PrimeCurveAffine;
use group::Curve;
use rand::thread_rng;
use std::io::Error;

#[derive(Default)]
pub struct SigData<E: CurveAffine> {
	r: E::ScalarExt,
	s: E::ScalarExt,
	pk: E,
	m_hash: E::ScalarExt
}

impl<E: CurveAffine> SigData<E> {
	pub fn r(&self) -> E::ScalarExt {
		self.r
	}

	pub fn s(&self) -> E::ScalarExt {
		self.s
	}

	pub fn pk(&self) -> E {
		self.pk
	}

	pub fn m_hash(&self) -> E::ScalarExt {
		self.m_hash
	}
}

pub fn generate_signature<E: CurveAffine>() -> Result<SigData<E>, Error> {
	let mut rng = thread_rng();

	// generate a valid signature
	let generator = <E as PrimeCurveAffine>::generator();
	let sk = <E as CurveAffine>::ScalarExt::random(&mut rng);
	let pk = generator * sk;
	let pk: E = pk.to_affine();

	let m_hash = <E as CurveAffine>::ScalarExt::random(&mut rng);
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
		pk,
		m_hash,
	};
	Ok(sig_data)
}