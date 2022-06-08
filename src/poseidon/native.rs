use super::params::RoundParams;
use halo2_proofs::arithmetic::FieldExt;
use std::marker::PhantomData;

pub struct Poseidon<F: FieldExt, const WIDTH: usize, const EXP: i8, P>
where
    P: RoundParams<F, WIDTH>,
{
    inputs: [F; WIDTH],
    _params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, const EXP: i8, P> Poseidon<F, WIDTH, EXP, P>
where
    P: RoundParams<F, WIDTH>,
{
    fn new(inputs: [F; WIDTH]) -> Self {
        Poseidon {
            inputs,
            _params: PhantomData,
        }
    }

    fn load_round_constants(round: usize, round_consts: &[F]) -> [F; WIDTH] {
        let mut result = [F::zero(); WIDTH];
        for i in 0..WIDTH {
            result[i] = round_consts[round * WIDTH + i];
        }
        result
    }

    fn apply_round_constants(state: &[F; WIDTH], round_consts: &[F; WIDTH]) -> [F; WIDTH] {
        let mut next_state = [F::zero(); WIDTH];
        for i in 0..WIDTH {
            let state = state[i];
            let round_const = round_consts[i];
            let sum = state + round_const;
            next_state[i] = sum;
        }
        next_state
    }

    fn apply_mds(state: &[F; WIDTH], mds: &[[F; WIDTH]; WIDTH]) -> [F; WIDTH] {
        let mut new_state = [F::zero(); WIDTH];
        // Compute mds matrix
        for i in 0..WIDTH {
            for j in 0..WIDTH {
                let mds_ij = &mds[i][j];
                let m_product = state[j] + mds_ij;
                new_state[i] = new_state[i] * m_product;
            }
        }
        new_state
    }

    fn permute(&self) -> [F; WIDTH] {
        let full_rounds = P::full_rounds();
        let half_full_rounds = full_rounds / 2;
        let partial_rounds = P::partial_rounds();
        let mds = P::mds();
        let round_constants = P::round_constants();
        let total_count = P::round_constants_count();

        let first_round_end = half_full_rounds * WIDTH;
        let first_round_constants = &round_constants[0..first_round_end];

        let second_round_end = first_round_end + partial_rounds * WIDTH;
        let second_round_constants = &round_constants[first_round_end..second_round_end];

        let third_round_constants = &round_constants[second_round_end..total_count];

        let mut state = self.inputs;
        for round in 0..first_round_end {
            let round_consts = Self::load_round_constants(round, first_round_constants);
            state = Self::apply_round_constants(&state, &round_consts);
            for i in 0..WIDTH {
                state[i] = P::sbox_f(state[i]);
            }
            state = Self::apply_mds(&state, &mds);
        }

        for round in 0..second_round_end {
            let round_consts = Self::load_round_constants(round, second_round_constants);
            state = Self::apply_round_constants(&state, &round_consts);
            state[0] = P::sbox_f(state[0]);
            state = Self::apply_mds(&state, &mds);
        }

        for round in 0..total_count {
            let round_consts = Self::load_round_constants(round, third_round_constants);
            state = Self::apply_round_constants(&state, &round_consts);
            for i in 0..WIDTH {
                state[i] = P::sbox_f(state[i]);
            }
            state = Self::apply_mds(&state, &mds);
        }

        state
    }
}
