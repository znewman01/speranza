use thiserror::Error;

use crate::certificate::{Inner as CertificateInner, PredicateVerifier};
use crate::commitments::Scheme;
use crate::signature::ContextVerifier;

fn extract_commitment<C: Scheme, V>(
    certificate: &CertificateInner<V>,
) -> Result<C::Commitment, <C::Commitment as TryFrom<Vec<u8>>>::Error>
where
    C: Scheme,
    C::Commitment: TryFrom<Vec<u8>>,
{
    certificate.subject.0.clone().try_into()
}

#[derive(Debug, Error)]
pub enum Error<E> {
    #[error("extracting commitment: {0}")]
    ExtractingCommitment(#[from] E),
    #[error("commitment equality proof failed")]
    EqualityProof,
}

type InnerError<C> = Error<<<C as Scheme>::Commitment as TryFrom<Vec<u8>>>::Error>;
type CocoVerifier<V1, V2, C> =
    PredicateVerifier<V1, V2, <C as Scheme>::EqualityProof, InnerError<C>>;

pub fn coco_verifier<V1, V2, C>(params: C, c1: C::Commitment) -> CocoVerifier<V1, V2, C>
where
    C: Scheme + 'static,
    C::Commitment: TryFrom<Vec<u8>> + 'static,
    V1: ContextVerifier,
    V2: ContextVerifier,
{
    PredicateVerifier::new(Box::new(move |cert, proof| {
        let c2 = extract_commitment::<C, _>(cert)?;
        if !params.verify_equality(&c1, &c2, proof) {
            return Err(Error::EqualityProof);
        }
        Ok(())
    }))
}
