use std::marker::PhantomData;

use ed25519_dalek as ed25519;

#[cfg(test)]
use proptest::prelude::*;

use super::{Bundle, Certificate, FixedCertSigner, Identity, Inner, Subject};
use crate::signature::{ContextSigner, ContextVerifier};
use crate::util::Canonicalize;

pub trait CertificateAuthority {
    type Verifier: ContextVerifier;
    type ExtraRequest;
    type ExtraResponse;

    fn verifier(&self) -> Self::Verifier;

    fn issue<V>(
        &self,
        identity: Identity,
        key: V,
    ) -> (
        Certificate<V, <Self::Verifier as ContextVerifier>::Signature>,
        Self::ExtraResponse,
    )
    where
        V: ContextVerifier,
        Inner<V>: Canonicalize;
}

#[derive(Debug)]
pub struct Ed25519Ca {
    key: ed25519::Keypair,
    subject: Subject,
}

impl Ed25519Ca {
    pub fn new(key: ed25519::Keypair, subject: Subject) -> Self {
        Self { key, subject }
    }
}

#[cfg(test)]
impl Arbitrary for Ed25519Ca {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use crate::signature::tests::key_pairs;
        (key_pairs(), any::<Subject>())
            .prop_map(|(key, subject)| Ed25519Ca::new(key, subject))
            .boxed()
    }
}

impl CertificateAuthority for Ed25519Ca {
    type Verifier = ed25519::PublicKey;
    type ExtraRequest = ();
    type ExtraResponse = ();

    fn verifier(&self) -> Self::Verifier {
        self.key.public
    }

    fn issue<V>(
        &self,
        identity: Identity,
        key: V,
    ) -> (Certificate<V, ed25519::Signature>, Self::ExtraResponse)
    where
        V: ContextVerifier,
        Inner<V>: Canonicalize,
    {
        (self.key.wrap(Inner::new(identity.into(), key), &()), ())
    }
}

#[derive(Debug)]
pub struct CaSigner<C, K, V> {
    subject: Identity,
    key: K,
    public_key: V,
    _ca: PhantomData<C>,
}

impl<C, K, V> CaSigner<C, K, V> {
    pub fn new(subject: Identity, key: K, public_key: V) -> Self {
        Self {
            subject,
            key,
            public_key,
            _ca: PhantomData,
        }
    }
}

impl<C, K, V> ContextSigner for CaSigner<C, K, V>
where
    K: ContextSigner<Signature = V::Signature>,
    V: ContextVerifier + Clone,
    C: CertificateAuthority,
    Inner<V>: Canonicalize,
    Certificate<V, <C::Verifier as ContextVerifier>::Signature>: Clone,
{
    type Context = (C, K::Context);
    type Signature = Bundle<V, <C::Verifier as ContextVerifier>::Signature>;

    fn sign_bytes(&self, msg: &[u8], (ca, context): &Self::Context) -> Self::Signature {
        let (cert, _) = ca.issue(self.subject.clone(), self.public_key.clone());
        let signer = FixedCertSigner::new(&self.key, &cert);
        signer.sign_bytes(msg, context)
    }
}
