use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
struct Opinion<F: FieldExt> {
    local_score: F,
    global_score: F,
}

impl<F: FieldExt> Opinion<F> {
    fn new(local_score: F, global_score: F) -> Self {
        Opinion {
            local_score,
            global_score,
        }
    }

    fn calculate_score(&self) -> F {
        self.local_score * self.global_score
    }
}

#[derive(Clone, Debug)]
struct FieldConfig<F: FieldExt> {
    advices: [Column<Advice>; 4],
    instance: Column<Instance>,
    s_mul: Selector,
    _marker: PhantomData<F>,
}

#[derive(Default)]
struct MyCircuit<F: FieldExt> {
    opinions: Vec<Option<Opinion<F>>>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = FieldConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice1 = meta.advice_column();
        let advice2 = meta.advice_column();
        let advice3 = meta.advice_column();
        let advice4 = meta.advice_column();

        let instance = meta.instance_column();

        let s_mul = meta.selector();

        meta.enable_equality(advice1);
        meta.enable_equality(advice4);
        meta.enable_equality(instance);

        meta.create_gate("accumulator", |v_cells| {
            let sum = v_cells.query_advice(advice1, Rotation::cur());
            let lhs = v_cells.query_advice(advice2, Rotation::cur());
            let rhs = v_cells.query_advice(advice3, Rotation::cur());
            let out = v_cells.query_advice(advice4, Rotation::cur());
            let s = v_cells.query_selector(s_mul);

            vec![s * (sum + (lhs * rhs) - out)]
        });

        FieldConfig {
            advices: [advice1, advice2, advice3, advice4],
            instance,
            s_mul,
            _marker: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let global_score = layouter.assign_region(
            || "accumulator",
            |mut region: Region<'_, F>| {
                let mut accumulated_cell: Option<AssignedCell<F, F>> = None;
                for i in 0..self.opinions.len() {
                    if let Some(opinion) = &self.opinions[i] {
                        // Set selector as enabled
                        config.s_mul.enable(&mut region, i)?;

                        let sum_cell = if let Some(accumulated_cell) = accumulated_cell {
                            accumulated_cell.copy_advice(
                                || "acc",
                                &mut region,
                                config.advices[0],
                                i,
                            )?
                        } else {
                            region.assign_advice(
                                || "acc",
                                config.advices[0],
                                i,
                                || Ok(F::zero()),
                            )?
                        };

                        let lhs_cell = region.assign_advice(
                            || "lhs",
                            config.advices[1],
                            i,
                            || Ok(opinion.local_score),
                        )?;
                        let rhs_cell = region.assign_advice(
                            || "rhs",
                            config.advices[2],
                            i,
                            || Ok(opinion.global_score),
                        )?;

                        let value = lhs_cell
                            .value()
                            .and_then(|&a| rhs_cell.value().map(|&b| a * b));
                        let out_score = sum_cell.value().and_then(|&sum| value.map(|v| sum + v));

                        let out = region.assign_advice(
                            || "out",
                            config.advices[3],
                            i,
                            || out_score.ok_or(Error::Synthesis),
                        )?;

                        accumulated_cell = Some(out);
                    }
                }
                accumulated_cell.ok_or(Error::Synthesis)
            },
        )?;

        // Expose the result as a public input to the circuit.
        layouter.constrain_instance(global_score.cell(), config.instance, 0)?;

        Ok(())
    }
}

pub fn main() {
    use halo2_proofs::{dev::MockProver, pairing::bn256::Fr as Fp};

    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 8;

    let opinion = Opinion::new(Fp::from(2), Fp::from(3));
    let final_score = opinion.calculate_score().double();

    // Instantiate the circuit with the private inputs.
    let circuit = MyCircuit {
        opinions: vec![Some(opinion); 2],
    };

    // Arrange the public input. We expose the multiplication result in row 0
    // of the instance column, so we position it there in our public inputs.
    let mut public_inputs = vec![final_score];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());

    // Create the area you want to draw on.
    // Use SVGBackend if you want to render to .svg instead.
    use plotters::prelude::*;
    let root = BitMapBackend::new("layout.png", (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Example Circuit Layout", ("sans-serif", 60))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .render(5, &circuit, &root)
        .unwrap();
}
