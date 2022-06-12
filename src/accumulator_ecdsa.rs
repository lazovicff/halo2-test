use ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use ecc::maingate::RegionCtx;
use ecc::{EccConfig, GeneralEccChip};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use integer::{IntegerInstructions, NUMBER_OF_LOOKUP_LIMBS};
use maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions};
use maingate::UnassignedValue;
use maingate::MainGateInstructions;
use std::marker::PhantomData;
use crate::ecdsa::SigData;

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;

#[derive(Clone, Debug)]
pub struct EcdsaVerifierConfig {
	main_gate_config: MainGateConfig,
	range_config: RangeConfig,
}

impl EcdsaVerifierConfig {
	pub fn config_range<N: FieldExt>(
		&self,
		layouter: &mut impl Layouter<N>,
	) -> Result<(), Error> {
		let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
		let range_chip = RangeChip::<N>::new(self.range_config.clone(), bit_len_lookup);
		range_chip.load_limb_range_table(layouter)?;
		range_chip.load_overflow_range_tables(layouter)?;

		Ok(())
	}
}

#[derive(Clone)]
pub struct EcdsaVerifier<E: CurveAffine, N: FieldExt> {
	lhs: [Option<N>; 4],
	rhs: [Option<N>; 4],
	sig_data: Option<SigData<E::ScalarExt>>,
	pk: Option<E>,
	m_hash: Option<E::ScalarExt>,
	aux_generator: Option<E>,
	window_size: usize,
	_marker: PhantomData<N>,
}

impl<E: CurveAffine, N: FieldExt> EcdsaVerifier<E, N> {
	pub fn new(
		lhs: [Option<N>; 4],
		rhs: [Option<N>; 4],
		sig_data: Option<SigData<E::Scalar>>,
		pk: Option<E>,
		m_hash: Option<E::Scalar>,
		aux_generator: Option<E>
	) -> Self {
		Self {
			lhs,
			rhs,
			sig_data,
			pk,
			m_hash,
			aux_generator,
			window_size: 2,
			_marker: PhantomData,
		}
	}
}

impl<E: CurveAffine, N: FieldExt> Circuit<N> for EcdsaVerifier<E, N> {
	type Config = EcdsaVerifierConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			lhs: [None; 4],
			rhs: [None; 4],
			sig_data: None,
			pk: None,
			m_hash: None,
			aux_generator: None,
			window_size: self.window_size,
			_marker: PhantomData
		}
	}

	fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
		let (rns_base, rns_scalar) =
			GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
		let main_gate_config = MainGate::<N>::configure(meta);
		let mut overflow_bit_lengths: Vec<usize> = vec![];
		overflow_bit_lengths.extend(rns_base.overflow_lengths());
		overflow_bit_lengths.extend(rns_scalar.overflow_lengths());
		let range_config =
			RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
		EcdsaVerifierConfig {
			main_gate_config,
			range_config,
		}
	}

	fn synthesize(
		&self,
		config: Self::Config,
		mut layouter: impl Layouter<N>,
	) -> Result<(), Error> {
		let mut ecc_chip = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
			EccConfig::new(config.range_config.clone(), config.main_gate_config.clone()),
		);
		let scalar_chip = ecc_chip.scalar_field_chip();
		let main_gate = MainGate::new(config.main_gate_config.clone());

		layouter.assign_region(
			|| "assign_aux",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				ecc_chip.assign_aux_generator(ctx, self.aux_generator)?;
				ecc_chip.assign_aux(ctx, self.window_size, 1)?;
				Ok(())
			},
		)?;

		let sum = layouter.assign_region(|| "acc", |mut region| {
			let main_gate = MainGate::new(config.main_gate_config.clone());

			let position = &mut 0;
			let ctx = &mut RegionCtx::new(&mut region, position);
			let unassigned_lhs = self.lhs.clone().map(|val| UnassignedValue::from(val));
			let unassigned_rhs = self.rhs.clone().map(|val| UnassignedValue::from(val));
			let assigned_lhs = unassigned_lhs.map(|val| main_gate.assign_value(ctx, &val).unwrap());
			let assigned_rhs = unassigned_rhs.map(|val| main_gate.assign_value(ctx, &val).unwrap());

			let mut sum = main_gate.assign_constant(ctx, N::zero())?;
			for i in 0..4 {
				let out = main_gate.mul(ctx, &assigned_lhs[i], &assigned_rhs[i])?;
				sum = main_gate.add(ctx, &sum, &out)?;
			}

			Ok(sum)
		})?;

		let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

		layouter.assign_region(
			|| "region 0",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				let integer_r = ecc_chip.new_unassigned_scalar(self.sig_data.map(|s| s.r));
				let integer_s = ecc_chip.new_unassigned_scalar(self.sig_data.map(|s| s.s));
				let msg_hash = ecc_chip.new_unassigned_scalar(self.m_hash);

				let r_assigned = scalar_chip.assign_integer(ctx, integer_r)?;
				let s_assigned = scalar_chip.assign_integer(ctx, integer_s)?;
				let sig = AssignedEcdsaSig {
					r: r_assigned,
					s: s_assigned,
				};

				let pk_in_circuit = ecc_chip.assign_point(ctx, self.pk.map(|p| p.into()))?;
				let pk_assigned = AssignedPublicKey {
					point: pk_in_circuit,
				};
				let msg_hash = scalar_chip.assign_integer(ctx, msg_hash)?;
				main_gate.assert_equal(ctx, &msg_hash.native(), &sum)?;

				ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
			},
		)?;

		config.config_range(&mut layouter)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::ecdsa::native::generate_signature;
	use ff::PrimeField;
use halo2_proofs::arithmetic::CurveAffine;
	use group::{Group, Curve};
	use rand::thread_rng;
    use secp256k1::{Secp256k1Affine as Secp256};
	use halo2_proofs::arithmetic::Field;
	use maingate::halo2::{
		dev::MockProver,
		pairing::bn256::Fr,
	};

	#[test]
	fn test_ecdsa_accumulator_verify() {
		let k = 20;
		let mut rng = thread_rng();

		let lhs = [(); 4].map(|_| Some(Fr::random(&mut rng)));
		let rhs = [(); 4].map(|_| Some(Fr::random(&mut rng)));

		let mut sum = Fr::zero();
		for i in 0..4 {
			let lhs_i = lhs[i].unwrap();
			let rhs_i = rhs[i].unwrap();
			let out = lhs_i * rhs_i;
			sum = sum + out;
		}

		let sk = <Secp256 as CurveAffine>::ScalarExt::random(&mut rng);
		let m_hash = <Secp256 as CurveAffine>::ScalarExt::from_repr(sum.to_repr()).unwrap();
		let (sig_data, pk) = generate_signature::<Secp256>(sk, m_hash).unwrap();

		let aux_generator = <Secp256 as CurveAffine>::CurveExt::random(&mut rng).to_affine();
		let sig_verifyer = EcdsaVerifier {
			lhs,
			rhs,
			sig_data: Some(sig_data),
			pk: Some(pk),
			m_hash: Some(m_hash),
			aux_generator: Some(aux_generator),
			window_size: 2,
			_marker: PhantomData,
		};
		let public_inputs = vec![vec![]];
		let prover = match MockProver::<Fr>::run(k, &sig_verifyer, public_inputs) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};
		assert_eq!(prover.verify(), Ok(()));
	}
}