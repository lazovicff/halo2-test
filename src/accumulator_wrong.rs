use std::marker::PhantomData;

use ecc::maingate::RegionCtx;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use maingate::{MainGateConfig, RangeConfig, AssignedValue, UnassignedValue, MainGate, MainGateInstructions};

pub struct AccumulatorChip<F: FieldExt, const SIZE: usize>(MainGate<F>);

impl <F: FieldExt, const SIZE: usize> AccumulatorChip<F, SIZE> {
	pub fn new(main_gate: MainGate<F>) -> Self {
		Self(main_gate)
	}
	pub fn main_gate(&self) -> &MainGate<F> {
		&self.0
	}
}

impl<F: FieldExt, const SIZE: usize> AccumulatorChip<F, SIZE>
{
    pub fn accumulate(
        &self,
		ctx: &mut RegionCtx<'_, '_, F>,
		lhs: [AssignedValue<F>; SIZE],
		rhs: [AssignedValue<F>; SIZE],
    ) -> Result<AssignedValue<F>, Error> {
		let main_gate = self.main_gate();

		let mut sum = main_gate.assign_constant(ctx, F::zero())?;
		for i in 0..SIZE {
			let out = main_gate.mul(ctx, &lhs[i], &rhs[i])?;
			sum = main_gate.add(ctx, &sum, &out)?;
		}

        Ok(sum)
    }
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2_proofs::circuit::SimpleFloorPlanner;
	use halo2_proofs::plonk::Circuit;
	use halo2_proofs::plonk::ConstraintSystem;
	use halo2_proofs::circuit::{Layouter, Region};
	use halo2_proofs::pairing::bn256::Fr;
	use halo2_proofs::dev::MockProver;

	#[derive(Clone, Debug)]
	struct TestConfig {
		main_gate_config: MainGateConfig,
	}

	struct TestCircuit<F: FieldExt> {
		lhs: [UnassignedValue<F>; 4],
		rhs: [UnassignedValue<F>; 4],
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(lhs: [UnassignedValue<F>; 4], rhs: [UnassignedValue<F>; 4]) -> Self {
			TestCircuit {
				lhs,
				rhs,
			}
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;
		fn without_witnesses(&self) -> Self {
			Self {
				lhs: [(); 4].map(|_| UnassignedValue::from(None)),
				rhs: [(); 4].map(|_| UnassignedValue::from(None)),
			}
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
			let main_gate = MainGate::configure(meta);
			TestConfig {
				main_gate_config: main_gate,
			}
		}

		fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
			let sum = layouter.assign_region(|| "acc", |mut region: Region<'_, F>| {
				let maingate = MainGate::new(config.main_gate_config.clone());

				let position = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, position);
				let assigned_lhs = self.lhs.clone().map(|val| maingate.assign_value(ctx, &val).unwrap());
				let assigned_rhs = self.rhs.clone().map(|val| maingate.assign_value(ctx, &val).unwrap());

				let accumulator = AccumulatorChip::<F, 4>(maingate);
				accumulator.accumulate(ctx, assigned_lhs, assigned_rhs)
			})?;

			let maingate = MainGate::new(config.main_gate_config.clone());
			maingate.expose_public(layouter, sum, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_accumulator_chip() {
		let lhs = [(); 4].map(|_| UnassignedValue::from(Some(Fr::one())));
		let rhs = [(); 4].map(|_| UnassignedValue::from(Some(Fr::one())));
		let out = Fr::from(4);
		let tester = TestCircuit::new(lhs, rhs);
		let k = 9;
        let prover = MockProver::run(k, &tester, vec![vec![out]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
	}
}