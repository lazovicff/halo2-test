#[cfg(test)]
mod test {
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, Region, SimpleFloorPlanner},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
        poly::Rotation,
    };

    #[derive(Clone, Debug)]
    pub struct TestConfig {
        lhs_column: Column<Advice>,
        rhs_column: Column<Advice>,
        output: Column<Advice>,
    }

    pub struct TestChip<F: FieldExt> {
        lhs: Option<F>,
        rhs: Option<F>,
    }

    impl<F: FieldExt> TestChip<F> {
        fn new() -> Self {
            TestChip {
                lhs: Some(F::from(1)),
                rhs: Some(F::from(1)),
            }
        }
    }

    impl<F: FieldExt> Circuit<F> for TestChip<F> {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            TestChip {
                lhs: None,
                rhs: None,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
            let lhs_column = meta.advice_column();
            let rhs_column = meta.advice_column();
            let output = meta.advice_column();

            meta.create_gate("sum", |v_cells| {
                let lhs = v_cells.query_advice(lhs_column, Rotation::cur());
                let rhs = v_cells.query_advice(rhs_column, Rotation::cur());
                let output = v_cells.query_advice(output, Rotation::cur());

                vec![(lhs * rhs) - output]
            });

            TestConfig {
                lhs_column,
                rhs_column,
                output,
            }
        }

        fn synthesize(
            &self,
            config: TestConfig,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "sum",
                |mut region: Region<'_, F>| {
                    let a = region.assign_advice(
                        || "lhs",
                        config.lhs_column,
                        0,
                        || self.lhs.ok_or(Error::Synthesis),
                    )?;

                    let b = region.assign_advice(
                        || "lhs",
                        config.rhs_column,
                        0,
                        || self.rhs.ok_or(Error::Synthesis),
                    )?;

                    let c = a
                        .value()
                        .and_then(|&a_val| b.value().map(|&b_val| a_val * b_val));

                    let d = region.assign_advice(
                        || "out",
                        config.output,
                        0,
                        || c.ok_or(Error::Synthesis),
                    )?;

                    Ok(d)
                },
            )?;

            Ok(())
        }
    }
}
