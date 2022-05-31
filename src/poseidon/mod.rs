use std::marker::PhantomData;

mod sbox;
mod params;

use params::RoundParams;
use sbox::Sbox;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector, Fixed, Expression}, poly::Rotation,
};

#[derive(Clone, Debug)]
struct PoseidonConfig<F: FieldExt, const WIDTH: usize> {
	state: [Column<Advice>; WIDTH],
	round_params: [Column<Fixed>; WIDTH],
	mds: [[Column<Fixed>; WIDTH]; WIDTH],
	selector: Selector,
    _marker: PhantomData<F>,
}

struct Poseidon<F: FieldExt, const WIDTH: usize, const EXP: i8, P: RoundParams<F, WIDTH, EXP>> {
	inputs: [Option<F>; WIDTH],
	_params: PhantomData<P>,
}

impl<
	F: FieldExt,
	const WIDTH: usize,
	const EXP: i8,
	P: RoundParams<F, WIDTH, EXP>
> Circuit<F> for Poseidon<F, WIDTH, EXP, P> {
    type Config = PoseidonConfig<F, WIDTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
		Self {
			inputs: [None; WIDTH],
			_params: PhantomData,
		}
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
		let state = [(); WIDTH].map(|_| meta.advice_column());
        let round_params = [(); WIDTH].map(|_| meta.fixed_column());
		let mds = [[(); WIDTH]; WIDTH].map(|vec| vec.map(|_| meta.fixed_column()));
		let selector = meta.selector();

		meta.create_gate("full_round", |v_cells| {
			let mut exprs = [(); WIDTH].map(|_| Expression::Constant(F::zero()));
			// Add round constants
			for i in 0..WIDTH {
				let curr_state = v_cells.query_advice(state[i], Rotation::cur());
				let round_constant = v_cells.query_fixed(round_params[i], Rotation::cur());
				exprs[i] = Sbox::<EXP>::permute(curr_state + round_constant);
			}
			// Mat mul with MDS
			for i in 0..WIDTH {
				for j in 0..WIDTH {
					let mds_ij = v_cells.query_fixed(mds[i][j], Rotation::cur());
					exprs[j] = exprs[j].clone() * mds_ij;
				}
			}

			let s_cells = v_cells.query_selector(selector);
			// It should be equal to the state in next row
			for i in 0..WIDTH {
				let next_state = v_cells.query_advice(state[i], Rotation::next());
				exprs[i] = s_cells.clone() * (exprs[i].clone() - next_state);
			}

			exprs
		});

		meta.create_gate("partial_round", |v_cells| {
			let mut exprs = [(); WIDTH].map(|_| Expression::Constant(F::zero()));
			// Add round constants
			for i in 0..WIDTH {
				let curr_state = v_cells.query_advice(state[i], Rotation::cur());
				let round_constant = v_cells.query_fixed(round_params[i], Rotation::cur());
				exprs[i] = curr_state + round_constant;
			}
			exprs[0] = Sbox::<EXP>::permute(exprs[0].clone());
			// Mat mul with MDS
			for i in 0..WIDTH {
				for j in 0..WIDTH {
					let mds_ij = v_cells.query_fixed(mds[i][j], Rotation::cur());
					exprs[j] = exprs[j].clone() * mds_ij;
				}
			}

			let s_cells = v_cells.query_selector(selector);
			// It should be equal to the state in next row
			for i in 0..WIDTH {
				let next_state = v_cells.query_advice(state[i], Rotation::next());
				exprs[i] = s_cells.clone() * (exprs[i].clone() - next_state);
			}

			exprs
		});

        PoseidonConfig {
            state,
			round_params,
			mds,
			selector,
            _marker: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
		let round_params_count = P::round_constants_count();
		layouter.assign_region(|| "full_rounds", |mut region: Region<'_, F>| {

			Ok(())
		});
		Ok(())
    }
}