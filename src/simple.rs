use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    poly::Rotation,
};

#[derive(Clone, Debug)]
struct FieldConfig<F: FieldExt> {
    advice1: Column<Advice>,
    advice2: Column<Advice>,
    advice3: Column<Advice>,
    instance: Column<Instance>,
    _marker: PhantomData<F>,
}

#[derive(Default)]
struct MyCircuit<F: FieldExt> {
    a: Option<F>,
    b: Option<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = FieldConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that FieldChip uses for I/O.
        let advice1 = meta.advice_column();
        let advice2 = meta.advice_column();
        let advice3 = meta.advice_column();

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();

		meta.enable_equality(advice3);
		meta.enable_equality(instance);

        meta.create_gate("mul", |v_cells| {
            let lhs = v_cells.query_advice(advice1, Rotation::cur());
            let rhs = v_cells.query_advice(advice2, Rotation::cur());
            let out = v_cells.query_advice(advice3, Rotation::cur());

            vec![lhs * rhs - out]
        });

        FieldConfig {
            advice1,
            advice2,
            advice3,
            instance,
            _marker: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        let c = layouter.assign_region(|| "mul", |mut region: Region<'_, F>| {
			let a_cell = region.assign_advice(|| "private", config.advice1, 0, || self.a.ok_or(Error::Synthesis))?;
			let b_cell = region.assign_advice(|| "private", config.advice2, 0, || self.b.ok_or(Error::Synthesis))?;
			// Now we can assign the multiplication result, which is to be assigned
			// into the output position.
			let value = a_cell.value().and_then(|a| b_cell.value().map(|b| *a * *b));

			// Finally, we do the assignment to the output, returning a
			// variable to be used in another part of the circuit.
			region.assign_advice(|| "out", config.advice3, 0, || value.ok_or(Error::Synthesis))
		})?;

        // Expose the result as a public input to the circuit.
        layouter.constrain_instance(c.cell(), config.instance, 0)
    }
}

pub fn main() {
    use halo2_proofs::{dev::MockProver, pairing::bn256::Fr as Fp};

    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 4;

    // Prepare the private and public inputs to the circuit!
    let a = Fp::from(2);
    let b = Fp::from(3);
    let c = a * b;

    // Instantiate the circuit with the private inputs.
    let circuit = MyCircuit {
        a: Some(a),
        b: Some(b),
    };

    // Arrange the public input. We expose the multiplication result in row 0
    // of the instance column, so we position it there in our public inputs.
    let mut public_inputs = vec![c];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());
}
