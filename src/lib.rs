#![feature(array_try_map)]

mod poseidon;
mod ecdsa;

use ::ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
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
use poseidon::wrong::PoseidonChip;
use poseidon::params::RoundParams;
use std::marker::PhantomData;
use crate::ecdsa::SigData;

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;

type PoseidonChip5x5<F, P> = PoseidonChip<F, 5, P>;

#[derive(Clone, Debug)]
pub struct EigenTrustConfig {
	main_gate_config: MainGateConfig,
	range_config: RangeConfig,
}

impl EigenTrustConfig {
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
pub struct EigenTrustCircuit<
	E: CurveAffine,
	N: FieldExt,
	const SIZE: usize,
	P: RoundParams<N, 5>
> {
	op_v: Option<N>,
	pubkey_i: Option<E>,
	pubkey_v: Option<E>,
	sig_i: Option<SigData<E::ScalarExt>>,
	m_hash: Option<E::ScalarExt>,
	epoch: Option<N>,
	opinions: [Option<N>; SIZE],
	c_v: [Option<N>; SIZE],
	pubkeys: [Option<E>; SIZE],
	sigs: [Option<SigData<E::ScalarExt>>; SIZE],
	aux_generator: Option<E>,
	window_size: usize,
	_marker: PhantomData<N>,
	_params: PhantomData<P>,
}

impl<
	E: CurveAffine,
	N: FieldExt,
	const SIZE: usize,
	P: RoundParams<N, 5>
> EigenTrustCircuit<E, N, SIZE, P> {
	pub fn new(
		op_v: Option<N>,
		pubkey_i: Option<E>,
		pubkey_v: Option<E>,
		sig_i: Option<SigData<E::ScalarExt>>,
		m_hash: Option<E::ScalarExt>,
		epoch: Option<N>,
		opinions: [Option<N>; SIZE],
		c_v: [Option<N>; SIZE],
		pubkeys: [Option<E>; SIZE],
		sigs: [Option<SigData<E::ScalarExt>>; SIZE],
		aux_generator: Option<E>
	) -> Self {
		Self {
			op_v,
			pubkey_i,
			pubkey_v,
			sig_i,
			m_hash,
			epoch,
			opinions,
			c_v,
			pubkeys,
			sigs,
			aux_generator,
			window_size: 2,
			_marker: PhantomData,
			_params: PhantomData,
		}
	}
}

impl<
	E: CurveAffine,
	N: FieldExt,
	const SIZE: usize,
	P: RoundParams<N, 5>
> Circuit<N> for EigenTrustCircuit<E, N, SIZE, P> {
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			op_v: None,
			pubkey_i: None,
			pubkey_v: None,
			sig_i: None,
			m_hash: None,
			epoch: None,
			opinions: [None; SIZE],
			c_v: [None; SIZE],
			pubkeys: [None; SIZE],
			sigs: [None; SIZE],
			aux_generator: None,
			window_size: self.window_size,
			_marker: PhantomData,
			_params: PhantomData,
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
		EigenTrustConfig {
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

		let t_i = layouter.assign_region(|| "t_i", |mut region| {
			let position = &mut 0;
			let ctx = &mut RegionCtx::new(&mut region, position);
			let unassigned_ops = self.opinions.clone().map(|val| UnassignedValue::from(val));
			let assigned_ops = unassigned_ops.map(|val| main_gate.assign_value(ctx, &val).unwrap());

			let mut sum = main_gate.assign_constant(ctx, N::zero())?;
			for i in 0..SIZE {
				sum = main_gate.add(ctx, &sum, &assigned_ops[i])?;
			}

			Ok(sum)
		})?;

		let c_v = layouter.assign_region(|| "c_v", |mut region| {
			let position = &mut 0;
			let ctx = &mut RegionCtx::new(&mut region, position);
			let assigned_pks = self.pubkeys.try_map(|pk| ecc_chip.assign_point(ctx, pk.into()))?;
			let assigned_pk_v = ecc_chip.assign_point(ctx, self.pubkey_v)?;
			let unassigned_c_v = self.c_v.map(|val| UnassignedValue::from(val));
			let assigned_c_v = unassigned_c_v.try_map(|c| main_gate.assign_value(ctx, &c))?;

			let mut final_c_v = main_gate.assign_constant(ctx, N::zero())?;
			for i in 0..SIZE {
				let pk = &assigned_pks[i];
				let is_eq_x = main_gate.is_equal(ctx, &pk.get_x().native(), &assigned_pk_v.get_x().native())?;
				let is_eq_y = main_gate.is_equal(ctx, &pk.get_y().native(), &assigned_pk_v.get_y().native())?;
				let is_eq = main_gate.and(ctx, &is_eq_x, &is_eq_y)?;
				let product = main_gate.mul(ctx, &is_eq.into(), &assigned_c_v[i])?;
				final_c_v = main_gate.add(ctx, &final_c_v, &product)?;
			}

			Ok(final_c_v)
		})?;

		let opv = layouter.assign_region(|| "op_v", |mut region| {
			let position = &mut 0;
			let ctx = &mut RegionCtx::new(&mut region, position);
			
			let unassigned_opv = UnassignedValue::from(self.op_v);
			let assigned_opv = main_gate.assign_value(ctx, &unassigned_opv)?;
			let res = main_gate.mul(ctx, &t_i, &c_v)?;
			main_gate.assert_equal(ctx, &assigned_opv, &res)?;

			Ok(res)
		})?;

		let m_hash = layouter.assign_region(|| "m_hash", |mut region| {
			let position = &mut 0;
			let ctx = &mut RegionCtx::new(&mut region, position);

			let unassigned_epoch = UnassignedValue::from(self.epoch);
			let assigned_epoch =  main_gate.assign_value(ctx, &unassigned_epoch)?;
			let unassigned_m_hash = ecc_chip.new_unassigned_scalar(self.m_hash);
			let assigned_m_hash = scalar_chip.assign_integer(ctx, unassigned_m_hash)?;

			let zero = main_gate.assign_constant(ctx, N::zero())?;

			let input = [zero, assigned_epoch, opv, zero, zero];
			let poseidon = PoseidonChip5x5::<N, P>::new(config.main_gate_config.clone());
			let out = poseidon.permute(ctx, input)?[0];
			main_gate.assert_equal(ctx, &assigned_m_hash.native(), &out)?;

			Ok(assigned_m_hash)
		})?;

		let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

		layouter.assign_region(
			|| "sig_i_verify",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				let integer_r = ecc_chip.new_unassigned_scalar(self.sig_i.map(|s| s.r));
				let integer_s = ecc_chip.new_unassigned_scalar(self.sig_i.map(|s| s.s));

				let r_assigned = scalar_chip.assign_integer(ctx, integer_r)?;
				let s_assigned = scalar_chip.assign_integer(ctx, integer_s)?;
				let sig = AssignedEcdsaSig {
					r: r_assigned,
					s: s_assigned,
				};

				let pk_in_circuit = ecc_chip.assign_point(ctx, self.pubkey_i.map(|p| p.into()))?;
				let pk_assigned = AssignedPublicKey {
					point: pk_in_circuit,
				};

				ecdsa_chip.verify(ctx, &sig, &pk_assigned, &m_hash)
			},
		)?;

		layouter.assign_region(|| "sigs_verify", |mut region| {
			let offset = &mut 0;
			let ctx = &mut RegionCtx::new(&mut region, offset);

			for i in 0..SIZE {
				let integer_r = ecc_chip.new_unassigned_scalar(self.sigs[i].map(|s| s.r));
				let integer_s = ecc_chip.new_unassigned_scalar(self.sigs[i].map(|s| s.s));

				let r_assigned = scalar_chip.assign_integer(ctx, integer_r)?;
				let s_assigned = scalar_chip.assign_integer(ctx, integer_s)?;
				let sig = AssignedEcdsaSig {
					r: r_assigned,
					s: s_assigned,
				};

				let pk_in_circuit = ecc_chip.assign_point(ctx, self.pubkeys[i].map(|p| p.into()))?;
				let pk_assigned = AssignedPublicKey {
					point: pk_in_circuit,
				};

				ecdsa_chip.verify(ctx, &sig, &pk_assigned, &m_hash)?;
			}

			Ok(())
		})?;

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
	fn test_eigen_trust_verify() {

	}
}