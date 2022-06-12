mod accumulator;
mod accumulator_wrong;
mod accumulator_ecdsa;
mod poseidon;
mod ecdsa;

use std::marker::PhantomData;

use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::Error;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::circuit::Layouter;

use accumulator::OpinionConfig;
use accumulator::Opinion;
use accumulator::OpinionCircuit;
use halo2_proofs::plonk::Instance;
use crate::ecdsa::EcdsaVerifierConfig;
use crate::ecdsa::EcdsaVerifier;
use crate::ecdsa::SigData;

#[derive(Clone)]
struct EigenTrustConfig {
	opinion_config: OpinionConfig,
	ecdsa_config: EcdsaVerifierConfig,
	public_column: Column<Instance>
}

struct EigenTrustCircuit<
	E: CurveAffine,
	F: FieldExt,
	const SIZE: usize,
> {
	global_score: Option<F>,
	sig_data: Option<SigData<E::ScalarExt>>,
	pk: Option<E>,
	m_hash: Option<E::ScalarExt>,
	aux_generator: Option<E>,
	neighbour_sig_data: [Option<SigData<E::ScalarExt>>; SIZE],
	neighbour_pub_keys: [Option<E>; SIZE],
	neighbour_m_hashes: [Option<E::ScalarExt>; SIZE],
	neighbour_opinions: [Option<Opinion<F>>; SIZE],
	selectors: [bool; SIZE],
	_e: PhantomData<E>,
}

impl<
	E: CurveAffine,
	F: FieldExt,
	const SIZE: usize,
> Circuit<F> for EigenTrustCircuit<E, F, SIZE> {
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			global_score: None,
			sig_data: None,
			pk: None,
			m_hash: None,
			aux_generator: None,
			neighbour_sig_data: [None; SIZE],
			neighbour_pub_keys: [None; SIZE],
			neighbour_m_hashes: [None; SIZE],
			neighbour_opinions: [None; SIZE],
			selectors: self.selectors,
			_e: PhantomData,
		}
	}

	fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
		let opinion_config = OpinionCircuit::<F, SIZE>::configure(meta);
		let ecdsa_config = EcdsaVerifier::<E, F>::configure(meta);

		let instance = meta.instance_column();

		EigenTrustConfig {
			opinion_config,
			ecdsa_config,
			public_column: instance
		}
	}

	fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
		let op_circuit = OpinionCircuit::new(self.neighbour_opinions);
		let ecdsa_verifier = EcdsaVerifier::<E, F>::new(self.sig_data, self.pk, self.m_hash, self.aux_generator);

		ecdsa_verifier.synthesize(config.ecdsa_config.clone(), layouter.namespace(|| "sig_self"))?;
		let global_score = op_circuit.synthesize(config.opinion_config, layouter.namespace(|| "opinion_self"))?;

		layouter.constrain_instance(global_score.cell(), config.public_column, 0)?;

		for i in 0..SIZE {
			let ecdsa_verifier_i = EcdsaVerifier::<E, F>::new(
				self.neighbour_sig_data[i],
				self.neighbour_pub_keys[i],
				self.neighbour_m_hashes[i],
				self.aux_generator
			);
			ecdsa_verifier_i.synthesize(config.ecdsa_config.clone(), layouter.namespace(|| format!("sig_self_{}", i)))?;
		}
		Ok(())
	}
}