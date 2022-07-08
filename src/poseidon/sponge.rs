use std::marker::PhantomData;

use super::params::RoundParams;
use super::PoseidonConfig;
use crate::poseidon::PoseidonChip;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Advice;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Expression;
use halo2_proofs::plonk::{Column, Selector};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{arithmetic::FieldExt, circuit::AssignedCell, plonk::Error};

#[derive(Clone)]
struct PoseidonSpongeConfig<const WIDTH: usize> {
    poseidon_config: PoseidonConfig<WIDTH>,
    state: [Column<Advice>; WIDTH],
    absorb_selector: Selector,
}

struct PoseidonSpongeChip<F: FieldExt, const WIDTH: usize, P>
where
    P: RoundParams<F, WIDTH>,
{
    inputs: Vec<AssignedCell<F, F>>,
    _params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonSpongeChip<F, WIDTH, P>
where
    P: RoundParams<F, WIDTH>,
{
    fn new() -> Self {
        Self {
            inputs: Vec::new(),
            _params: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonSpongeConfig<WIDTH> {
        let poseidon_config = PoseidonChip::<_, WIDTH, P>::configure(meta);
        let state = [(); WIDTH].map(|_| {
            let column = meta.advice_column();
            meta.enable_equality(column);
            column
        });
        let absorb_selector = meta.selector();

        meta.create_gate("absorb", |v_cells| {
            let mut exprs = [(); WIDTH].map(|_| Expression::Constant(F::zero()));

            let s = v_cells.query_selector(absorb_selector);
            for i in 0..WIDTH {
                let poseidon_exp = v_cells.query_advice(poseidon_config.state[i], Rotation::cur());
                let sponge_exp = v_cells.query_advice(state[i], Rotation::cur());
                let next_sponge_exp = v_cells.query_advice(state[i], Rotation::next());
                let diff = next_sponge_exp - (sponge_exp + poseidon_exp);
                exprs[i] = s.clone() * diff;
            }

            exprs
        });

        PoseidonSpongeConfig {
            poseidon_config,
            state,
            absorb_selector,
        }
    }

    fn load_state(
        columns: [Column<Advice>; WIDTH],
        region: &mut Region<'_, F>,
        round: usize,
        prev_state: &[AssignedCell<F, F>],
    ) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
        let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
        for i in 0..WIDTH {
			if let Some(cell) = prev_state.get(i) {
				state[i] = Some(cell.copy_advice(|| "state", region, columns[i], round)?);
			} else {
				state[i] = Some(region.assign_advice(|| "state", columns[i], round, || Ok(F::zero()))?);
			}
        }
        Ok(state.map(|item| item.unwrap()))
    }

	fn load_chunks(
		&self,
		columns: [Column<Advice>; WIDTH],
		region: &mut Region<'_, F>,
	) -> Result<Vec<[AssignedCell<F, F>; WIDTH]>, Error> {
		let mut chunks = Vec::new();
		for (i, chunk) in self.inputs.chunks(WIDTH).enumerate() {
			let state_chunk = Self::load_state(columns, region, i, chunk)?;
			chunks.push(state_chunk);
		}
		Ok(chunks)
	}

    fn update(&mut self, inputs: &[AssignedCell<F, F>]) {
        self.inputs.extend_from_slice(inputs);
    }

    pub fn squeeze(
        &self,
        config: &PoseidonSpongeConfig<WIDTH>,
        mut layouter: impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        assert!(self.inputs.len() > 0);

		let inputs = layouter.assign_region(
			|| "load_chunks",
			|mut region: Region<'_, F>| self.load_chunks(config.state, &mut region)
		)?;

        let mut state = inputs[0].clone();

        for (i, chunk) in inputs.iter().skip(1).enumerate() {
            let pos = PoseidonChip::<_, WIDTH, P>::new(state);
            let perm_state = pos.permute(
                &config.poseidon_config,
                layouter.namespace(|| format!("absorb_{}", i)),
            )?;

            state = layouter.assign_region(
                || format!("absorb_{}", i),
                |mut region: Region<'_, F>| {
                    let round = 0;
                    config.absorb_selector.enable(&mut region, round)?;

                    let state = Self::load_state(config.state, &mut region, round, chunk)?;
                    let poseidon_state = Self::load_state(
                        config.poseidon_config.state,
                        &mut region,
                        round,
                        &perm_state,
                    )?;

                    let next_state = state.zip(poseidon_state).zip(config.state).try_map(
                        |((prev_state, pos_state), column)| {
                            let sum = prev_state
                                .value()
                                .and_then(|&s| pos_state.value().map(|&ps| s + ps));
                            region.assign_advice(
                                || "sum",
                                column,
                                round + 1,
                                || sum.ok_or(Error::Synthesis),
                            )
                        },
                    )?;

                    Ok(next_state)
                },
            )?;
        }

        Ok(state[0].clone())
    }
}

#[cfg(test)]
mod test {
    use super::{PoseidonSpongeChip, PoseidonSpongeConfig};
    use crate::poseidon::native::sponge::PoseidonSponge;

    use crate::poseidon::params::{bn254_5x5::Params5x5Bn254, hex_to_field};

    use halo2_proofs::{
        circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner},
        dev::MockProver,
        pairing::bn256::Fr,
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
    };

    type TestPoseidonSponge = PoseidonSponge<Fr, 5, Params5x5Bn254>;

    type TestPoseidonSpongeChip = PoseidonSpongeChip<Fr, 5, Params5x5Bn254>;

    #[derive(Clone)]
    struct PoseidonTesterConfig {
        sponge: PoseidonSpongeConfig<5>,
        results: Column<Instance>,
    }

    struct PoseidonTester {
        inputs1: [Option<Fr>; 5],
        inputs2: [Option<Fr>; 5],
    }

    impl PoseidonTester {
        fn new(inputs1: [Fr; 5], inputs2: [Fr; 5]) -> Self {
            Self {
                inputs1: inputs1.map(|item| Some(item)),
                inputs2: inputs2.map(|item| Some(item)),
            }
        }
    }

    impl PoseidonTester {
        fn load_state(
            config: &PoseidonSpongeConfig<5>,
            region: &mut Region<'_, Fr>,
            round: usize,
            init_state: [Option<Fr>; 5],
        ) -> Result<[AssignedCell<Fr, Fr>; 5], Error> {
            let mut state: [Option<AssignedCell<Fr, Fr>>; 5] = [(); 5].map(|_| None);
            for i in 0..5 {
                state[i] = Some(region.assign_advice(
                    || "state",
                    config.state[i],
                    round,
                    || init_state[i].ok_or(Error::Synthesis),
                )?);
            }
            Ok(state.map(|item| item.unwrap()))
        }
    }

    impl Circuit<Fr> for PoseidonTester {
        type Config = PoseidonTesterConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                inputs1: [None; 5],
                inputs2: [None; 5],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let sponge_config = TestPoseidonSpongeChip::configure(meta);
            let results = meta.instance_column();

            meta.enable_equality(results);

            Self::Config {
                sponge: sponge_config,
                results,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let inputs1 = layouter.assign_region(
                || "load_state1",
                |mut region: Region<'_, Fr>| {
                    Self::load_state(&config.sponge, &mut region, 0, self.inputs1)
                },
            )?;

            let inputs2 = layouter.assign_region(
                || "load_state2",
                |mut region: Region<'_, Fr>| {
                    Self::load_state(&config.sponge, &mut region, 0, self.inputs2)
                },
            )?;

            let mut poseidon_sponge = TestPoseidonSpongeChip::new();
            poseidon_sponge.update(&inputs1);
            poseidon_sponge.update(&inputs2);
            let result_state = poseidon_sponge
                .squeeze(&config.sponge, layouter.namespace(|| "poseidon_sponge"))?;

            layouter.constrain_instance(result_state.cell(), config.results, 0)?;
            Ok(())
        }
    }

    #[test]
    fn should_match_native_sponge() {
        let inputs1: [Fr; 5] = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000000000000000000000000000003",
            "0x0000000000000000000000000000000000000000000000000000000000000004",
        ]
        .map(|n| hex_to_field(n));

        let inputs2: [Fr; 5] = [
            "0x0000000000000000000000000000000000000000000000000000000000000005",
            "0x0000000000000000000000000000000000000000000000000000000000000006",
            "0x0000000000000000000000000000000000000000000000000000000000000007",
            "0x0000000000000000000000000000000000000000000000000000000000000008",
            "0x0000000000000000000000000000000000000000000000000000000000000009",
        ]
        .map(|n| hex_to_field(n));

        let mut sponge = TestPoseidonSponge::new();
        sponge.update(&inputs1);
        sponge.update(&inputs2);

        let native_result = sponge.squeeze();

        let poseidon_sponge = PoseidonTester::new(inputs1, inputs2);

        let k = 9;
        let prover = MockProver::run(k, &poseidon_sponge, vec![vec![native_result]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
