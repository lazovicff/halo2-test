use std::marker::PhantomData;

use halo2_proofs::plonk::{Column, Selector};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{arithmetic::FieldExt, circuit::AssignedCell, plonk::Error};
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::Region;
use crate::poseidon::PoseidonChip;
use halo2_proofs::plonk::Expression;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Advice;
use super::PoseidonConfig;
use super::params::RoundParams;

struct PoseidonSpongeConfig<const WIDTH: usize> {
	poseidon_config: PoseidonConfig<WIDTH>,
	inputs: [Column<Advice>; WIDTH],
	absorb_selector: Selector,
}

struct PoseidonSpongeChip<F: FieldExt, const WIDTH: usize, P>
where
    P: RoundParams<F, WIDTH>
{
	inputs: Vec<[AssignedCell<F, F>; WIDTH]>,
	_params: PhantomData<P>
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonSpongeChip<F, WIDTH, P>
where
    P: RoundParams<F, WIDTH>
{
	fn new() -> Self {
		Self {
			inputs: Vec::new(),
			_params: PhantomData
		}
	}

	fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonSpongeConfig<WIDTH> {
		let poseidon_config = PoseidonChip::<_, WIDTH, P>::configure(meta);
		let inputs = [(); WIDTH].map(|_| meta.advice_column());
		let absorb_selector = meta.selector();

		meta.create_gate("absorb", |v_cells| {
			let mut exprs = [(); WIDTH].map(|_| Expression::Constant(F::zero()));

			let s = v_cells.query_selector(absorb_selector);
			for i in 0..WIDTH {
				let poseidon_state = v_cells.query_advice(poseidon_config.state[i], Rotation::cur());
				let sponge_state = v_cells.query_advice(inputs[i], Rotation::cur());
				let next_sponge_state = v_cells.query_advice(inputs[i], Rotation::next());
				let diff = next_sponge_state - (sponge_state + poseidon_state);
				exprs[i] = s.clone() * diff;
			}

			exprs
		});

		PoseidonSpongeConfig {
			poseidon_config,
			inputs,
			absorb_selector,
		}
	}

	fn copy_state(
		columns: [Column<Advice>; WIDTH],
        region: &mut Region<'_, F>,
        round: usize,
        prev_state: [AssignedCell<F, F>; WIDTH],
    ) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
        let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
        for i in 0..WIDTH {
            state[i] =
                Some(prev_state[i].copy_advice(|| "state", region, columns[i], round)?);
        }
        Ok(state.map(|item| item.unwrap()))
    }

	fn update(&mut self, inputs: [AssignedCell<F, F>; WIDTH]) {
		self.inputs.push(inputs);
	}
	
	pub fn squeeze(
        &self,
		config: &PoseidonSpongeConfig<WIDTH>,
		mut layouter: impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
		assert!(self.inputs.len() > 0);

        let mut state = self.inputs[0].clone();

        for (i, chunk) in self.inputs.iter().enumerate() {
			let pos = PoseidonChip::<_, WIDTH, P>::new(state.clone());
            let perm_state = pos.permute(&config.poseidon_config, layouter.namespace(|| format!("absorb_{}", i)))?;

			state = layouter.assign_region(
				|| format!("absorb_{}", i),
				|mut region: Region<'_, F>| {
					let round = 0;
					config.absorb_selector.enable(&mut region, round)?;

					let state = Self::copy_state(config.inputs, &mut region, round, chunk.clone())?;
					let poseidon_state = Self::copy_state(config.poseidon_config.state, &mut region, round, perm_state.clone())?;

					let next_state = state.zip(poseidon_state).zip(config.inputs).try_map(|((prev_state, pos_state), column)| {
						let sum = prev_state.value().and_then(|&s| pos_state.value().map(|&ps| s + ps));
						region.assign_advice(|| "sum", column, round + 1, || sum.ok_or(Error::Synthesis))
					})?;

					Ok(next_state)
				}
			)?;
        }

        Ok(state[0].clone())
    }
}