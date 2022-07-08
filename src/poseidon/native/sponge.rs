use crate::poseidon::{native::Poseidon, RoundParams};
use halo2_proofs::arithmetic::FieldExt;
use std::marker::PhantomData;

pub struct PoseidonSponge<F: FieldExt, const WIDTH: usize, P>
where
    P: RoundParams<F, WIDTH>,
{
    inputs: Vec<F>,
    _params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonSponge<F, WIDTH, P>
where
    P: RoundParams<F, WIDTH>,
{
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            _params: PhantomData,
        }
    }

    pub fn update(&mut self, inputs: &[F]) {
        self.inputs.extend_from_slice(inputs);
    }

	pub fn load_chunks(&self) -> Vec<[F; WIDTH]> {
		let mut chunks = Vec::new();
		for chunk in self.inputs.chunks(WIDTH) {
			let mut state_chunk = [F::zero(); WIDTH];
			state_chunk[..chunk.len()].copy_from_slice(&chunk);
			chunks.push(state_chunk);
		}
		chunks
	}

    pub fn squeeze(&mut self) -> F {
        assert!(self.inputs.len() > 0);

		let inputs = self.load_chunks();

        let mut state = inputs[0];

        for chunk in inputs.iter().skip(1) {
            let pos = Poseidon::<_, WIDTH, P>::new(state);
            let perm_state = pos.permute();
            state = chunk.zip(perm_state).map(|(lhs, rhs)| lhs + rhs);
        }

        state[0]
    }
}
