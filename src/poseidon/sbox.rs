use halo2_proofs::plonk::Expression;
use halo2_proofs::arithmetic::FieldExt;

#[derive(Clone, Debug)]
pub struct Sbox<const EXP: i8>;

impl<const EXP: i8> Sbox<EXP> {
	pub fn permute<F: FieldExt>(exp: Expression<F>) -> Expression<F> {
		match EXP {
			5 => {
				let exp2 = exp.clone() * exp.clone();
				exp2.clone() * exp2 * exp
			}
			_ => panic!("unimplemented"),
		}
	}
}