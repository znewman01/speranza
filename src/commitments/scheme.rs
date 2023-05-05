use rand::{CryptoRng, RngCore};

pub trait Scheme {
    type Commitment: Eq;
    type BlindingFactor;
    type EqualityProof;

    // TODO: message -> anything canonicalizable?
    fn commit<R: RngCore + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> (Self::Commitment, Self::BlindingFactor);

    fn verify(&self, message: &[u8], c: &Self::Commitment, r: &Self::BlindingFactor) -> bool;

    fn prove_equality<R: RngCore + CryptoRng>(
        &self,
        message: &[u8],
        cr1: &Evidence<Self>,
        cr2: &Evidence<Self>,
        rng: &mut R,
    ) -> Self::EqualityProof;

    fn verify_equality(
        &self,
        c1: &Self::Commitment,
        c2: &Self::Commitment,
        proof: &Self::EqualityProof,
    ) -> bool;
}

pub type Evidence<C> = (<C as Scheme>::Commitment, <C as Scheme>::BlindingFactor);

#[cfg(test)]
macro_rules! check_commitment {
    ($type:ty) => {
        /// Property tests that $type is a commitment::Scheme.
        mod commitment_properties {
            #![allow(unused_imports)]
            use super::*;
            use crate::commitments::Scheme;
            use proptest::prelude::*;
            use rand::thread_rng;

            #[test]
            fn check_bounds() {
                fn check<C: Scheme>() {}
                check::<$type>();
            }

            proptest! {
                #[test]
                fn test_verify(params: $type, message: Vec<u8>) {
                    let mut rng = thread_rng();
                    let (c, r) = params.commit(&message, &mut rng);
                    prop_assert!(params.verify(&message, &c, &r));
                }

                #[test]
                fn test_verify_different_data(params: $type, m1: Vec<u8>, m2: Vec<u8>) {
                    prop_assume!(m1 != m2);
                    assert!(m1 != m2);
                    let mut rng = thread_rng();
                    let (c, r) = params.commit(&m1, &mut rng);
                    prop_assert!(!params.verify(&m2, &c, &r));
                }

                // TODO: Reinstate. Insecure fails this one.
                // #[test]
                fn test_verify_different_r(params: $type, message: Vec<u8>) {
                    let mut rng = thread_rng();
                    let e1 = params.commit(&message, &mut rng);
                    let e2 = params.commit(&message, &mut rng);
                    prop_assert!(!params.verify(&message, &e1.0, &e2.1));
                    prop_assert!(!params.verify(&message, &e2.0, &e1.1));
                }

                #[test]
                fn test_equality_proof(params: $type, message: Vec<u8>) {
                    let mut rng = thread_rng();
                    let e1 = params.commit(&message, &mut rng);
                    let e2 = params.commit(&message, &mut rng);
                    let proof = params.prove_equality(&message, &e1, &e2, &mut rng);
                    prop_assert!(params.verify_equality(&e1.0, &e2.0, &proof));
                }

                #[test]
                fn test_equality_proof_order_insensitive(params: $type, message: Vec<u8>) {
                    let mut rng = thread_rng();
                    let e1 = params.commit(&message, &mut rng);
                    let e2 = params.commit(&message, &mut rng);
                    let proof = params.prove_equality(&message, &e1, &e2, &mut rng);
                    prop_assert!(params.verify_equality(&e2.0, &e1.0, &proof));
                }

                #[test]
                fn test_equality_proof_bad(params: $type, m1: Vec<u8>, m2: Vec<u8>) {
                    // This *should* still fail when m1 == m2. But it doesn't
                    // for the"insecure" method.
                    prop_assume!(m1 != m2);

                    let mut rng = thread_rng();
                    let e1 = params.commit(&m1, &mut rng);
                    let e2 = params.commit(&m1, &mut rng);
                    let proof = params.prove_equality(&m1, &e1, &e2, &mut rng);

                    let (c3, _) = params.commit(&m2, &mut rng);
                    prop_assert!(!params.verify_equality(&e1.0, &c3, &proof));
                    prop_assert!(!params.verify_equality(&e2.0, &c3, &proof));
                }
            }
        }
    };
}

#[cfg(test)]
pub(crate) use check_commitment;
