pub mod bn254_10x5;
pub mod bn254_5x5;

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Expression;
use maingate::MainGateInstructions;
use maingate::{AssignedValue, MainGate, RegionCtx};

pub trait RoundParams<F: FieldExt, const WIDTH: usize>: Sbox {
    fn full_rounds() -> usize;
    fn partial_rounds() -> usize;

    fn round_constants_count() -> usize {
        let partial_rounds = Self::partial_rounds();
        let full_rounds = Self::full_rounds();
        (partial_rounds + full_rounds) * WIDTH
    }

    fn round_constants() -> Vec<F> {
        let round_constants_raw = Self::round_constants_raw();
        let round_constants: Vec<F> = round_constants_raw
            .iter()
            .map(|x| hex_to_field(x))
            .collect();
        assert_eq!(round_constants.len(), Self::round_constants_count());
        round_constants
    }

    fn load_round_constants(round: usize, round_consts: &[F]) -> [F; WIDTH] {
        let mut result = [F::zero(); WIDTH];
        for i in 0..WIDTH {
            result[i] = round_consts[round * WIDTH + i];
        }
        result
    }

    fn mds() -> [[F; WIDTH]; WIDTH] {
        let mds_raw = Self::mds_raw();
        let mds = mds_raw.map(|row| row.map(|item| hex_to_field(item)));
        mds
    }

    fn round_constants_raw() -> Vec<&'static str>;
    fn mds_raw() -> [[&'static str; WIDTH]; WIDTH];
}

pub trait Sbox {
    fn sbox_expr<F: FieldExt>(exp: Expression<F>) -> Expression<F>;
    fn sbox_asgn<F: FieldExt>(
        main_gate: &MainGate<F>,
        ctx: &mut RegionCtx<'_, '_, F>,
        exp: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>;
    fn sbox_f<F: FieldExt>(f: F) -> F;
}

pub fn hex_to_field<F: FieldExt>(s: &str) -> F {
    let s = &s[2..];
    let mut bytes = hex::decode(s).expect("Invalid params");
    bytes.reverse();
    let mut bytes_wide: [u8; 64] = [0; 64];
    for i in 0..bytes.len() {
        bytes_wide[i] = bytes[i];
    }
    F::from_bytes_wide(&bytes_wide)
}
