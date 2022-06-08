use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug, Copy)]
pub struct Opinion<F: FieldExt> {
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
pub struct OpinionConfig {
    advices: [Column<Advice>; 4],
    s_mul: Selector,
}

pub struct OpinionCircuit<F: FieldExt, const SIZE: usize> {
    opinions: [Option<Opinion<F>>; SIZE],
}

impl <F: FieldExt, const SIZE: usize> Default for OpinionCircuit<F, SIZE> {
	fn default() -> Self {
		Self {
			opinions: [None; SIZE],
		}
	}
}

impl<F: FieldExt, const SIZE: usize> OpinionCircuit<F, SIZE> {
	pub fn new(opinions: [Option<Opinion<F>>; SIZE]) -> Self {
		Self { opinions }
	}
}

impl<F: FieldExt, const SIZE: usize> OpinionCircuit<F, SIZE> {
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> OpinionConfig {
        let advice1 = meta.advice_column();
        let advice2 = meta.advice_column();
        let advice3 = meta.advice_column();
        let advice4 = meta.advice_column();

        let s_mul = meta.selector();

        meta.enable_equality(advice1);
        meta.enable_equality(advice4);

        meta.create_gate("accumulator", |v_cells| {
            let sum = v_cells.query_advice(advice1, Rotation::cur());
            let lhs = v_cells.query_advice(advice2, Rotation::cur());
            let rhs = v_cells.query_advice(advice3, Rotation::cur());
            let out = v_cells.query_advice(advice4, Rotation::cur());
            let s = v_cells.query_selector(s_mul);

            vec![s * (sum + (lhs * rhs) - out)]
        });

        OpinionConfig {
            advices: [advice1, advice2, advice3, advice4],
            s_mul,
        }
    }

    pub fn synthesize(
        &self,
        config: OpinionConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
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

        Ok(global_score)
    }
}