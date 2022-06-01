use std::marker::PhantomData;

mod params;
mod sbox;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Region},
    plonk::{Advice, Column, Constraint, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use params::RoundParams;
use sbox::Sbox;

#[derive(Clone, Debug)]
pub struct PoseidonConfig<F: FieldExt, const WIDTH: usize> {
    state: [Column<Advice>; WIDTH],
    round_params: [Column<Fixed>; WIDTH],
    mds: [[Column<Fixed>; WIDTH]; WIDTH],
    full_round_selector: Selector,
    partial_round_selector: Selector,
    _marker: PhantomData<F>,
}

pub struct Poseidon<F: FieldExt, const WIDTH: usize, const EXP: i8, P: RoundParams<F, WIDTH, EXP>> {
    inputs: [Option<F>; WIDTH],
    _params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, const EXP: i8, P: RoundParams<F, WIDTH, EXP>>
    Poseidon<F, WIDTH, EXP, P>
{
    fn new(inputs: [Option<F>; WIDTH]) -> Self {
        Poseidon {
            inputs,
            _params: PhantomData,
        }
    }

    fn load_state(
        config: &PoseidonConfig<F, WIDTH>,
        region: &mut Region<'_, F>,
        round: usize,
        init_state: [Option<F>; WIDTH],
    ) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
        let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
        for i in 0..WIDTH {
            state[i] = Some(region.assign_advice(
                || "state",
                config.state[i],
                round,
                || init_state[i].ok_or(Error::Synthesis),
            )?);
        }
        Ok(state.map(|item| item.unwrap()))
    }

    fn copy_state(
        config: &PoseidonConfig<F, WIDTH>,
        region: &mut Region<'_, F>,
        round: usize,
        prev_state: &[AssignedCell<F, F>; WIDTH],
    ) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
        let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
        for i in 0..WIDTH {
            state[i] =
                Some(prev_state[i].copy_advice(|| "state", region, config.state[i], round)?);
        }
        Ok(state.map(|item| item.unwrap()))
    }

    fn load_round_constants(
        config: &PoseidonConfig<F, WIDTH>,
        region: &mut Region<'_, F>,
        round: usize,
        round_constants: &[F],
    ) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
        let mut round_cells: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
        for i in 0..WIDTH {
            round_cells[i] = Some(region.assign_fixed(
                || "round_constant",
                config.round_params[i],
                round,
                || Ok(round_constants[round * WIDTH + i]),
            )?);
        }
        Ok(round_cells.map(|item| item.unwrap()))
    }

    fn load_mds(
        config: &PoseidonConfig<F, WIDTH>,
        region: &mut Region<'_, F>,
        round: usize,
        mds: &[[F; WIDTH]; WIDTH],
    ) -> Result<[[AssignedCell<F, F>; WIDTH]; WIDTH], Error> {
        let mut mds_cells: [[Option<AssignedCell<F, F>>; WIDTH]; WIDTH] =
            [[(); WIDTH]; WIDTH].map(|vec| vec.map(|_| None));
        for i in 0..WIDTH {
            for j in 0..WIDTH {
                mds_cells[i][j] = Some(region.assign_fixed(
                    || "mds",
                    config.mds[i][j],
                    round,
                    || Ok(mds[i][j]),
                )?);
            }
        }
        Ok(mds_cells.map(|vec| vec.map(|item| item.unwrap())))
    }
}

impl<F: FieldExt, const WIDTH: usize, const EXP: i8, P: RoundParams<F, WIDTH, EXP>>
    Poseidon<F, WIDTH, EXP, P>
{
    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, WIDTH> {
        let state = [(); WIDTH].map(|_| {
            let column = meta.advice_column();
            meta.enable_equality(column);
            column
        });
        let round_params = [(); WIDTH].map(|_| meta.fixed_column());
        let mds = [[(); WIDTH]; WIDTH].map(|vec| vec.map(|_| meta.fixed_column()));
        let full_round_selector = meta.selector();
        let partial_round_selector = meta.selector();

        meta.create_gate("full_round", |v_cells| {
            let mut exprs = [(); WIDTH].map(|_| Expression::Constant(F::zero()));
            // Add round constants
            for i in 0..WIDTH {
                let curr_state = v_cells.query_advice(state[i], Rotation::cur());
                let round_constant = v_cells.query_fixed(round_params[i], Rotation::cur());
                exprs[i] = Sbox::<EXP>::permute_expr(curr_state + round_constant);
            }
            // Mat mul with MDS
            for i in 0..WIDTH {
                for j in 0..WIDTH {
                    let mds_ij = v_cells.query_fixed(mds[i][j], Rotation::cur());
                    exprs[j] = exprs[j].clone() * mds_ij;
                }
            }

            let s_cells = v_cells.query_selector(full_round_selector);
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
            exprs[0] = Sbox::<EXP>::permute_expr(exprs[0].clone());

            // Mat mul with MDS
            for i in 0..WIDTH {
                for j in 0..WIDTH {
                    let mds_ij = v_cells.query_fixed(mds[i][j], Rotation::cur());
                    exprs[j] = exprs[j].clone() * mds_ij;
                }
            }

            let s_cells = v_cells.query_selector(partial_round_selector);
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
            full_round_selector,
            partial_round_selector,
            _marker: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<F, WIDTH>,
        mut layouter: impl Layouter<F>,
    ) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
        let full_rounds = P::full_rounds();
        let half_full_rounds = full_rounds / 2;
        let partial_rounds = P::partial_rounds();
        let mds = P::mds();
        let round_constants = P::round_constants();
        let total_cound = P::round_constants_count();

        let first_round_end = half_full_rounds * WIDTH;
        let first_round_constants = &round_constants[0..first_round_end];

        let second_round_end = (half_full_rounds * WIDTH) + partial_rounds * WIDTH;
        let second_round_constants = &round_constants[first_round_end..second_round_end];

        let third_round_constants = &round_constants[second_round_end..total_cound];

        let state1 = layouter.assign_region(
            || "full_rounds_1",
            |mut region: Region<'_, F>| {
                // Assign initial state
                let mut state_cells = Self::load_state(&config, &mut region, 0, self.inputs)?;
                for round in 0..half_full_rounds {
                    config.full_round_selector.enable(&mut region, round)?;

                    // Assign round constants
                    let round_const_cells = Self::load_round_constants(
                        &config,
                        &mut region,
                        round,
                        first_round_constants,
                    )?;
                    // Assign mds matrix
                    let mds_cells = Self::load_mds(&config, &mut region, round, &mds)?;

                    let mut next_state = [None; WIDTH];
                    // Compute full round
                    for i in 0..WIDTH {
                        let state = &state_cells[i];
                        let round_const = &round_const_cells[i];
                        let sum = state
                            .value()
                            .and_then(|&s| round_const.value().map(|&r| s + r));
                        next_state[i] = Sbox::<EXP>::permute_opt_f(sum);
                    }

                    let temp_state = next_state.clone();
                    // Compute mds matrix
                    for i in 0..WIDTH {
                        for j in 0..WIDTH {
                            let mds_ij = &mds_cells[i][j];
                            let m_product =
                                temp_state[j].and_then(|s| mds_ij.value().map(|&m| s * m));
                            next_state[i] = next_state[i].and_then(|a| m_product.map(|b| a + b));
                        }
                    }

                    // Assign next state
                    for i in 0..WIDTH {
                        state_cells[i] = region.assign_advice(
                            || "state",
                            config.state[i],
                            round + 1,
                            || next_state[i].ok_or(Error::Synthesis),
                        )?;
                    }
                }
                Ok(state_cells)
            },
        )?;

        let state2 = layouter.assign_region(
            || "partial_rounds",
            |mut region: Region<'_, F>| {
                let mut state_cells = Self::copy_state(&config, &mut region, 0, &state1)?;
                for round in 0..partial_rounds {
                    config.partial_round_selector.enable(&mut region, round)?;

                    // Assign round constants
                    let round_const_cells = Self::load_round_constants(
                        &config,
                        &mut region,
                        round,
                        second_round_constants,
                    )?;
                    // Assign mds matrix
                    let mds_cells = Self::load_mds(&config, &mut region, round, &mds)?;

                    let mut next_state = [None; WIDTH];
                    // Compute full round
                    for i in 0..WIDTH {
                        let state = &state_cells[i];
                        let round_const = &round_const_cells[i];
                        let sum = state
                            .value()
                            .and_then(|&s| round_const.value().map(|&r| s + r));
                        next_state[i] = sum;
                    }
                    next_state[0] = Sbox::<EXP>::permute_opt_f(next_state[0]);

                    let temp_state = next_state.clone();
                    // Compute mds matrix
                    for i in 0..WIDTH {
                        for j in 0..WIDTH {
                            let mds_ij = &mds_cells[i][j];
                            let m_product =
                                temp_state[j].and_then(|s| mds_ij.value().map(|&m| s * m));
                            next_state[i] = next_state[i].and_then(|a| m_product.map(|b| a + b));
                        }
                    }

                    // Assign next state
                    for i in 0..WIDTH {
                        state_cells[i] = region.assign_advice(
                            || "state",
                            config.state[i],
                            round + 1,
                            || next_state[i].ok_or(Error::Synthesis),
                        )?;
                    }
                }
                Ok(state_cells)
            },
        )?;

        let state3 = layouter.assign_region(
            || "full_rounds_2",
            |mut region: Region<'_, F>| {
                let mut state_cells = Self::copy_state(&config, &mut region, 0, &state2)?;
                for round in 0..half_full_rounds {
                    config.full_round_selector.enable(&mut region, round)?;

                    // Assign round constants
                    let round_const_cells = Self::load_round_constants(
                        &config,
                        &mut region,
                        round,
                        third_round_constants,
                    )?;
                    // Assign mds matrix
                    let mds_cells = Self::load_mds(&config, &mut region, round, &mds)?;

                    let mut next_state = [None; WIDTH];
                    // Compute full round
                    for i in 0..WIDTH {
                        let state = &state_cells[i];
                        let round_const = &round_const_cells[i];
                        let sum = state
                            .value()
                            .and_then(|&s| round_const.value().map(|&r| s + r));
                        next_state[i] = Sbox::<EXP>::permute_opt_f(sum);
                    }

                    let temp_state = next_state.clone();
                    // Compute mds matrix
                    for i in 0..WIDTH {
                        for j in 0..WIDTH {
                            let mds_ij = &mds_cells[i][j];
                            let m_product =
                                temp_state[j].and_then(|s| mds_ij.value().map(|&m| s * m));
                            next_state[i] = next_state[i].and_then(|a| m_product.map(|b| a + b));
                        }
                    }

                    // Assign next state
                    for i in 0..WIDTH {
                        state_cells[i] = region.assign_advice(
                            || "state",
                            config.state[i],
                            round + 1,
                            || next_state[i].ok_or(Error::Synthesis),
                        )?;
                    }
                }
                Ok(state_cells)
            },
        )?;

        println!("{:?}", state3.clone().map(|x| x.value().cloned()));

        Ok(state3)
    }
}

#[cfg(test)]
mod test {
    use core::panic;

    use super::params::{hex_to_field, Params5x5Bn254};
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        pairing::bn256::Fr,
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
    };

    type TestPoseidon = Poseidon<Fr, 5, 5, Params5x5Bn254>;

    #[derive(Clone)]
    struct PoseidonTesterConfig {
        poseidon_config: PoseidonConfig<Fr, 5>,
        results: Column<Instance>,
    }

    struct PoseidonTester {
        inputs: [Option<Fr>; 5],
    }

    impl PoseidonTester {
        fn new(inputs: [Option<Fr>; 5]) -> Self {
            Self { inputs }
        }
    }

    impl Circuit<Fr> for PoseidonTester {
        type Config = PoseidonTesterConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { inputs: [None; 5] }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let poseidon_config = TestPoseidon::configure(meta);
            let results = meta.instance_column();

            meta.enable_equality(results);
            for i in 0..5 {
                meta.enable_equality(poseidon_config.state[i]);
            }

            Self::Config {
                poseidon_config,
                results,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let poseidon = TestPoseidon::new(self.inputs);
            let result_state =
                poseidon.synthesize(config.poseidon_config, layouter.namespace(|| "poseidon"))?;
            for i in 0..5 {
                layouter.constrain_instance(result_state[i].cell(), config.results, i)?;
            }
            Ok(())
        }
    }

    #[test]
    fn test_poseidon_x5_5() {
        let inputs: [Option<Fr>; 5] = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000000000000000000000000000003",
            "0x0000000000000000000000000000000000000000000000000000000000000004",
        ]
        .map(|n| Some(hex_to_field(n)));

        let outputs: [Fr; 5] = [
            "0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465",
            "0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d",
            "0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907",
            "0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e",
            "0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7",
        ]
        .map(|n| hex_to_field(n));

        let poseidon_tester = PoseidonTester::new(inputs);

        let k = 9;
        let prover = MockProver::run(k, &poseidon_tester, vec![outputs.to_vec()]).unwrap();
        let res = prover.verify().err().unwrap();
        println!("{:?}", res[0]);
        panic!("{}", res.len());
    }
}
