use std::marker::PhantomData;

use curve25519_dalek::digest::consts::U64;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::ristretto::*;
use curve25519_dalek::scalar::*;
use derivative::Derivative;
#[cfg(test)]
use proptest::prelude::*;
use rand::{CryptoRng, RngCore};
use thiserror::Error;

use super::{Evidence, Scheme};
use crate::util::Canonicalize;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Commitment(RistrettoPoint);

impl Ord for Commitment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Ord::cmp(&self.0.compress().0, &other.0.compress().0)
    }
}

impl PartialOrd for Commitment {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(&self, &other))
    }
}

impl From<Commitment> for Vec<u8> {
    fn from(commitment: Commitment) -> Self {
        commitment.0.compress().to_bytes().to_vec()
    }
}

impl Canonicalize for Commitment {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::<u8>::from("pedersen Commitment:");
        data.extend(Vec::<u8>::from(*self));
        data
    }
}

#[derive(Debug, Error)]
#[error("couldn't convert to bytes")]
pub struct DecompressError;

impl From<DecompressError> for signature::Error {
    fn from(error: DecompressError) -> Self {
        signature::Error::from_source(error)
    }
}

impl TryFrom<Vec<u8>> for Commitment {
    type Error = DecompressError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let point = CompressedRistretto::from_slice(&bytes)
            .decompress()
            .ok_or(DecompressError)?;
        Ok(Commitment(point))
    }
}

#[derive(Copy, Clone)]
pub struct BlindingFactor(Scalar);

impl BlindingFactor {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }
}

/// Public parameters for Pedersen commitments.
#[derive(Clone, Copy, Derivative)]
#[derivative(Debug(bound = ""))]
pub struct Parameters<D: Digest> {
    g: RistrettoPoint,
    h: RistrettoPoint,
    _digest: PhantomData<D>,
}

#[cfg(test)]
impl<D> Arbitrary for Parameters<D>
where
    D: Digest<OutputSize = U64> + Default,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Vec<u8>>()
            .prop_map(|input| RistrettoPoint::hash_from_bytes::<D>(&input))
            .prop_flat_map(|points| (Just(points), Just(points)))
            .prop_map(|(g, h)| Self::new(g, h))
            .boxed()
    }
}

impl<D: Digest> Parameters<D> {
    pub fn new(g: RistrettoPoint, h: RistrettoPoint) -> Self {
        Self {
            g,
            h,
            _digest: PhantomData,
        }
    }

    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            g: RistrettoPoint::random(rng),
            h: RistrettoPoint::random(rng),
            _digest: PhantomData,
        }
    }

    fn commit_fixed(&self, m: Scalar, r: BlindingFactor) -> Commitment {
        Commitment(self.g * m + self.h * r.0)
    }
}

#[derive(Debug, Clone)]
pub struct EqualityProof {
    // commitment message
    c3: Commitment,
    c4: Commitment,

    // response
    z1: Scalar,
    z2: Scalar,
    z3: Scalar,
}

fn fiat_shamir<D: Digest<OutputSize = U64>>(
    c1: Commitment,
    c2: Commitment,
    c3: Commitment,
    c4: Commitment,
) -> Scalar {
    let mut hasher = <D as Digest>::new();
    hasher.update(c1.0.compress().to_bytes());
    hasher.update(c2.0.compress().to_bytes());
    hasher.update(c3.0.compress().to_bytes());
    hasher.update(c4.0.compress().to_bytes());
    Scalar::from_hash(hasher)
}

impl<D> Scheme for Parameters<D>
where
    D: Digest<OutputSize = U64> + Default,
{
    type Commitment = Commitment;
    type BlindingFactor = BlindingFactor;
    type EqualityProof = EqualityProof;

    fn commit<R: rand::RngCore + rand::CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> (Self::Commitment, Self::BlindingFactor) {
        let r = BlindingFactor::random(rng);
        let m = Scalar::hash_from_bytes::<D>(message);
        let c = self.commit_fixed(m, r);
        (c, r)
    }

    fn verify(&self, message: &[u8], c: &Self::Commitment, r: &Self::BlindingFactor) -> bool {
        let m = Scalar::hash_from_bytes::<D>(message);
        let c2 = Commitment((m * self.g) + (r.0 * self.h));
        c == &c2
    }

    fn prove_equality<R: rand::RngCore + rand::CryptoRng>(
        &self,
        message: &[u8],
        (mut c1, mut r1): &Evidence<Self>,
        (mut c2, mut r2): &Evidence<Self>,
        rng: &mut R,
    ) -> Self::EqualityProof {
        debug_assert!(self.verify(message, &c1, &r1));
        debug_assert!(self.verify(message, &c2, &r2));

        if c2 < c1 {
            ((c1, r1), (c2, r2)) = ((c2, r2), (c1, r1));
        }

        // Chaum-Pedersen proof.
        let m = Scalar::hash_from_bytes::<D>(message);

        let r3 = Scalar::random(rng);
        let r4 = BlindingFactor::random(rng);
        let r5 = BlindingFactor::random(rng);

        let c3 = self.commit_fixed(r3, r4);
        let c4 = self.commit_fixed(r3, r5);

        let challenge = fiat_shamir::<D>(c1, c2, c3, c4);

        let z1 = challenge * m + r3;
        let z2 = challenge * r1.0 + r4.0;
        let z3 = challenge * r2.0 + r5.0;

        EqualityProof { c3, c4, z1, z2, z3 }
    }

    fn verify_equality<'a>(
        &self,
        mut c1: &'a Self::Commitment,
        mut c2: &'a Self::Commitment,
        EqualityProof { c3, c4, z1, z2, z3 }: &Self::EqualityProof,
    ) -> bool {
        if c2 < c1 {
            (c2, c1) = (c1, c2);
        }
        let challenge = fiat_shamir::<D>(*c1, *c2, *c3, *c4);
        c3.0 + c1.0 * challenge == self.g * z1 + self.h * z2
            && c4.0 + c2.0 * challenge == self.g * z1 + self.h * z3
    }
}

#[cfg(test)]
super::check_commitment!(Parameters<sha2::Sha512>);
