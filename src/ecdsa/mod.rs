mod native;

use ecdsa::ecdsa::{EcdsaConfig, EcdsaChip, AssignedEcdsaSig, AssignedPublicKey};
use halo2_proofs::arithmetic::CurveAffine;
use maingate::{MainGate, RangeChip, RegionCtx, RangeConfig};
use ecc::integer::{IntegerInstructions, NUMBER_OF_LOOKUP_LIMBS};
use maingate::RangeInstructions;
use maingate::halo2::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use ecc::{GeneralEccChip};
use native::SigData;

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;

#[derive(Clone)]
struct EcdsaVerifyerConfig {
	range_config: RangeConfig,
	ecdsa_config: EcdsaConfig,
}

impl EcdsaVerifyerConfig {
	fn new(range_config: RangeConfig, ecdsa_config: EcdsaConfig) -> Self {
		EcdsaVerifyerConfig {
			range_config,
			ecdsa_config,
		}
	}

	pub fn range_config(&self) -> RangeConfig {
		self.range_config.clone()
	}

	pub fn ecdsa_config(&self) -> EcdsaConfig {
		self.ecdsa_config.clone()
	}
}

#[derive(Default)]
struct EcdsaVerifyer<E: CurveAffine> {
	sig_data: SigData<E>,
	aux_generator: E,
    window_size: usize,
}

impl<E: CurveAffine> EcdsaVerifyer<E> {
	pub fn new(sig_data: SigData<E>, aux_generator: E, window_size: usize) -> Self {
		EcdsaVerifyer {
			sig_data,
			aux_generator,
			window_size,
		}
	}
}

impl<E: CurveAffine> Circuit<E::ScalarExt> for EcdsaVerifyer<E> {
	type Config = EcdsaVerifyerConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<E::ScalarExt>) -> Self::Config {
		let (rns_base, rns_scalar) =
                GeneralEccChip::<E, E::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();

		let mut overflow_bit_lengths: Vec<usize> = Vec::new();
		overflow_bit_lengths.extend(rns_base.overflow_lengths());
		overflow_bit_lengths.extend(rns_scalar.overflow_lengths());

		let maingate_config = MainGate::configure(meta);
		let range_config = RangeChip::configure(meta, &maingate_config, overflow_bit_lengths);

		let ecds_config = EcdsaConfig::new(range_config.clone(), maingate_config);

		EcdsaVerifyerConfig::new(range_config, ecds_config)
	}

	fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<E::ScalarExt>) -> Result<(), Error> {
		let mut ecc_chip = GeneralEccChip::<E, E::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
			config.ecdsa_config().ecc_chip_config()
		);
		let scalar_chip = ecc_chip.scalar_field_chip();
		let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

		layouter.assign_region(
			|| "assign_aux",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				ecc_chip.assign_aux_generator(ctx, Some(self.aux_generator))?;
				ecc_chip.assign_aux(ctx, self.window_size, 1)?;
				Ok(())
			},
		)?;

		layouter.assign_region(
			|| "verify_region",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				let integer_r = ecc_chip.new_unassigned_scalar(Some(self.sig_data.r()));
				let integer_s = ecc_chip.new_unassigned_scalar(Some(self.sig_data.s()));
				let msg_hash = ecc_chip.new_unassigned_scalar(Some(self.sig_data.m_hash()));

				let r_assigned = scalar_chip.assign_integer(ctx, integer_r)?;
				let s_assigned = scalar_chip.assign_integer(ctx, integer_s)?;
				let sig = AssignedEcdsaSig {
					r: r_assigned,
					s: s_assigned,
				};

				let pk_in_circuit = ecc_chip.assign_point(ctx, Some(self.sig_data.pk()))?;
				let pk_assigned = AssignedPublicKey {
					point: pk_in_circuit,
				};
				let msg_hash = scalar_chip.assign_integer(ctx, msg_hash)?;
				ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
			},
		)?;

		let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
		let range_chip = RangeChip::<E::ScalarExt>::new(config.range_config(), bit_len_lookup);
		range_chip.load_limb_range_table(&mut layouter)?;
		range_chip.load_overflow_range_tables(&mut layouter)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use super::native::generate_signature;
	use rand::thread_rng;
	use group::{Group, Curve};
    use secp256k1::{Secp256k1Affine as Secp256};
	use maingate::halo2::{
		dev::MockProver,
	};

	#[test]
	fn test_ecdsa_verify() {
		let mut rng = thread_rng();

		let k = 20;
		let sig_data = generate_signature::<Secp256>().unwrap();
		let generator = <Secp256 as CurveAffine>::CurveExt::random(&mut rng).to_affine();
		let sig_verifyer = EcdsaVerifyer::new(sig_data, generator, 2);
		let public_inputs = vec![vec![]];
		let prover = match MockProver::run(k, &sig_verifyer, public_inputs) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};
		assert_eq!(prover.verify(), Ok(()));
	}
}