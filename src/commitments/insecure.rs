#[cfg(test)]
use proptest::prelude::*;

use super::{Evidence, Scheme};
use crate::util::Canonicalize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment(Vec<u8>);

impl From<Commitment> for Vec<u8> {
    fn from(commitment: Commitment) -> Self {
        commitment.0
    }
}

impl From<Vec<u8>> for Commitment {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl Canonicalize for Commitment {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::<u8>::from("dummy Commitment:");
        data.extend(&self.0);
        data
    }
}

#[derive(Copy, Clone)]
pub struct BlindingFactor;

/// Public parameters for insecure commitments.
#[derive(Clone, Debug)]
pub struct Parameters;

#[cfg(test)]
impl Arbitrary for Parameters {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        Just(Parameters).boxed()
    }
}

#[derive(Debug, Clone)]
pub struct EqualityProof;

impl Scheme for Parameters {
    type Commitment = Commitment;
    type BlindingFactor = BlindingFactor;
    type EqualityProof = EqualityProof;

    fn commit<R: rand::RngCore + rand::CryptoRng>(
        &self,
        message: &[u8],
        _: &mut R,
    ) -> (Self::Commitment, Self::BlindingFactor) {
        (Commitment(message.to_vec()), BlindingFactor)
    }

    fn verify(&self, message: &[u8], c: &Self::Commitment, _: &Self::BlindingFactor) -> bool {
        c.0 == message
    }

    fn prove_equality<R: rand::RngCore + rand::CryptoRng>(
        &self,
        message: &[u8],
        (c1, r1): &Evidence<Self>,
        (c2, r2): &Evidence<Self>,
        _: &mut R,
    ) -> Self::EqualityProof {
        assert!(self.verify(message, c1, r1));
        assert!(self.verify(message, c2, r2));

        EqualityProof
    }

    fn verify_equality(
        &self,
        c1: &Self::Commitment,
        c2: &Self::Commitment,
        _: &Self::EqualityProof,
    ) -> bool {
        c1 == c2
    }
}

#[cfg(test)]
super::check_commitment!(Parameters);
