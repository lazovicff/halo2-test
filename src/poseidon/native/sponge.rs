use halo2_proofs::arithmetic::FieldExt;
use crate::poseidon::{RoundParams, native::Poseidon};
use std::marker::PhantomData;

struct PoseidonSponge<F: FieldExt, const WIDTH: usize, P>
where
    P: RoundParams<F, WIDTH>
{
	inputs: Vec<[F; WIDTH]>,
	_params: PhantomData<P>
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonSponge<F, WIDTH, P>
where
    P: RoundParams<F, WIDTH>
{
	fn new() -> Self {
		Self {
			inputs: Vec::new(),
			_params: PhantomData
		}
	}

	fn update(&mut self, inputs: [F; WIDTH]) {
		self.inputs.push(inputs);
	}

	pub fn squeeze(
        &mut self,
    ) -> F {
		assert!(self.inputs.len() > 0);

		let mut state = self.inputs[0];

		for chunk in &self.inputs {
			let pos = Poseidon::<_, WIDTH, P>::new(state);
			let perm_state = pos.permute();
			state = chunk.zip(perm_state).map(|(lhs, rhs)| lhs + rhs);
		}

		state[0]
	}
}