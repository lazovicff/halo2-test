use ecc::maingate::{big_to_fe, fe_to_big};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::transcript::{Challenge255, Transcript, TranscriptRead, TranscriptWrite};
use std::marker::PhantomData;

/// Convert the number from base field to scalar field of elliptic curve.
fn base_to_scalar<C: CurveAffine>(x: C::Base) -> C::Scalar {
    let x_big = fe_to_big(x);
    big_to_fe(x_big)
}

// #[derive(Debug, Clone)]
// pub struct PoseidonRead<R: Read, C: CurveAffine, E: EncodedChallenge<C>> {
//     state: Poseidon<C::ScalarExt, POSEIDON_T, POSEIDON_RATE>,
//     reader: R,
//     _marker: PhantomData<(C, E)>,
// }

// impl<R: Read, C: CurveAffine, E: EncodedChallenge<C>> PoseidonRead<R, C, E> {
//     /// Initialize a transcript given an input buffer.
//     pub fn init(reader: R) -> Self {
//         PoseidonRead {
//             state: Poseidon::new(8usize, 33usize),
//             reader,
//             _marker: PhantomData,
//         }
//     }
// }

// impl<R: Read, C: CurveAffine> TranscriptRead<C, Challenge255<C>>
//     for PoseidonRead<R, C, Challenge255<C>>
// {
//     fn read_point(&mut self) -> io::Result<C> {
//         let mut compressed = C::Repr::default();
//         self.reader.read_exact(compressed.as_mut())?;
//         let point: C = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
//             io::Error::new(io::ErrorKind::Other, "invalid point encoding in proof")
//         })?;
//         self.common_point(point)?;

//         Ok(point)
//     }

//     fn read_scalar(&mut self) -> io::Result<C::Scalar> {
//         let mut data = <C::Scalar as PrimeField>::Repr::default();
//         self.reader.read_exact(data.as_mut())?;
//         let scalar: C::Scalar = Option::from(C::Scalar::from_repr(data)).ok_or_else(|| {
//             io::Error::new(
//                 io::ErrorKind::Other,
//                 "invalid field element encoding in proof",
//             )
//         })?;
//         self.common_scalar(scalar)?;

//         Ok(scalar)
//     }
// }

// impl<R: Read, C: CurveAffine> Transcript<C, Challenge255<C>>
//     for PoseidonRead<R, C, Challenge255<C>>
// {
//     fn squeeze_challenge(&mut self) -> Challenge255<C> {
//         let scalar = self.state.squeeze();
//         let mut bytes: Vec<u8> = Vec::new();
//         scalar.write(&mut bytes).unwrap();
//         bytes.resize(64, 0u8);
//         Challenge255::<C>::new(&bytes.try_into().unwrap())
//     }

//     fn common_point(&mut self, point: C) -> io::Result<()> {
//         let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or_else(|| {
//             io::Error::new(
//                 io::ErrorKind::Other,
//                 "cannot write points at infinity to the transcript",
//             )
//         })?;
//         let x = coords.x();
//         let y = coords.y();
//         self.state.update(&[base_to_scalar(x), base_to_scalar(y)]);

//         Ok(())
//     }

//     fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
//         //self.state.update(&[BLAKE2B_PREFIX_SCALAR]);
//         self.state.update(&[scalar]);

//         Ok(())
//     }
// }

// #[derive(Debug, Clone)]
// pub struct PoseidonWrite<W: Write, C: CurveAffine, E: EncodedChallenge<C>> {
//     state: Poseidon<C::ScalarExt, POSEIDON_T, POSEIDON_RATE>,
//     writer: W,
//     _marker: PhantomData<(C, E)>,
// }

// impl<W: Write, C: CurveAffine, E: EncodedChallenge<C>> PoseidonWrite<W, C, E> {
//     /// Initialize a transcript given an output buffer.
//     pub fn init(writer: W) -> Self {
//         PoseidonWrite {
//             state: Poseidon::new(8usize, 33usize),
//             writer,
//             _marker: PhantomData,
//         }
//     }

//     /// Conclude the interaction and return the output buffer (writer).
//     pub fn finalize(self) -> W {
//         // TODO: handle outstanding scalars? see issue #138
//         self.writer
//     }
// }

// impl<W: Write, C: CurveAffine> TranscriptWrite<C, Challenge255<C>>
//     for PoseidonWrite<W, C, Challenge255<C>>
// {
//     fn write_point(&mut self, point: C) -> io::Result<()> {
//         self.common_point(point)?;
//         let compressed = point.to_bytes();
//         self.writer.write_all(compressed.as_ref())
//     }
//     fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
//         self.common_scalar(scalar)?;
//         let data = scalar.to_repr();
//         self.writer.write_all(data.as_ref())
//     }
// }

// impl<W: Write, C: CurveAffine> Transcript<C, Challenge255<C>>
//     for PoseidonWrite<W, C, Challenge255<C>>
// {
//     fn squeeze_challenge(&mut self) -> Challenge255<C> {
//         let scalar = self.state.squeeze();
//         let mut bytes: Vec<u8> = Vec::new();
//         scalar.write(&mut bytes).unwrap();
//         bytes.resize(64, 0u8);
//         Challenge255::<C>::new(&bytes.try_into().unwrap())
//     }

//     fn common_point(&mut self, point: C) -> io::Result<()> {
//         //self.state.update(&[PREFIX_POINT]);
//         let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or_else(|| {
//             io::Error::new(
//                 io::ErrorKind::Other,
//                 "cannot write points at infinity to the transcript",
//             )
//         })?;
//         let x = coords.x();
//         let y = coords.y();
//         self.state.update(&[base_to_scalar(x), base_to_scalar(y)]);

//         Ok(())
//     }

//     fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
//         self.state.update(&[scalar]);

//         Ok(())
//     }
// }
