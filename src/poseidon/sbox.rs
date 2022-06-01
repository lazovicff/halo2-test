use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;

#[derive(Clone, Debug)]
pub struct Sbox<const EXP: i8>;

impl<const EXP: i8> Sbox<EXP> {
    pub fn permute_expr<F: FieldExt>(exp: Expression<F>) -> Expression<F> {
        match EXP {
            5 => {
                let exp2 = exp.clone() * exp.clone();
                exp2.clone() * exp2 * exp
            }
            _ => panic!("unimplemented"),
        }
    }

    pub fn permute_opt_f<F: FieldExt>(opt_f: Option<F>) -> Option<F> {
        match EXP {
            5 => opt_f.map(|f| {
                let f2 = f.clone() * f.clone();
                f2.clone() * f2 * f
            }),
            _ => panic!("unimplemented"),
        }
    }
}
