use ed25519_dalek as ed25519;
#[cfg(test)]
use proptest::prelude::*;

use crate::certificate::{
    Certificate, CertificateAuthority, Ed25519Ca, Identity, Inner as CertificateInner, Subject,
};
use crate::commitments::{Evidence, Pedersen, Scheme};
use crate::util::Canonicalize;

#[derive(Debug)]
pub struct CocoCa<C> {
    params: C,
    ca: Ed25519Ca,
}

impl<C> CocoCa<C> {
    pub fn new(params: C, ca: Ed25519Ca) -> Self {
        Self { params, ca }
    }

    pub fn params(&self) -> &C {
        &self.params
    }
}

impl CocoCa<Pedersen> {
    pub fn random() -> Self {
        CocoCa::new(
            Pedersen::random(&mut rand::thread_rng()),
            Ed25519Ca::new(
                ed25519::Keypair::generate(&mut rand::thread_rng()),
                Subject(vec![]),
            ),
        )
    }
}

#[cfg(test)]
impl<C> Arbitrary for CocoCa<C>
where
    C: Arbitrary,
    C::Strategy: 'static,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (any::<C>(), any::<Ed25519Ca>())
            .prop_map(|(params, ca)| Self::new(params, ca))
            .boxed()
    }
}

impl<C> CertificateAuthority for CocoCa<C>
where
    C: Scheme,
    C::Commitment: Into<Vec<u8>> + Copy,
{
    type Verifier = ed25519::PublicKey;
    type ExtraRequest = ();
    type ExtraResponse = Evidence<C>;

    fn verifier(&self) -> Self::Verifier {
        self.ca.verifier()
    }

    fn issue<V>(
        &self,
        identity: Identity,
        key: V,
    ) -> (
        Certificate<V, <Self::Verifier as crate::signature::ContextVerifier>::Signature>,
        Self::ExtraResponse,
    )
    where
        V: crate::signature::ContextVerifier,
        CertificateInner<V>: Canonicalize,
    {
        let (c, r) = self
            .params
            .commit(&identity.canonicalize(), &mut rand::thread_rng());
        let (cert, ()) = self.ca.issue(Identity(c.into()), key);
        (cert, (c, r))
    }
}
