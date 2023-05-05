use ed25519_dalek as ed25519;

use super::Subject;
use crate::signature::ContextVerifier;
use crate::util::Canonicalize;

/// A crude approximation of an unsigned certificate.
///
/// Much less complexity than X.509.
#[derive(Debug, Clone)]
pub struct Inner<V> {
    pub subject: Subject,
    public_key: V,
}

impl Canonicalize for Inner<ed25519::PublicKey> {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("certificate_inner:");
        data.extend(&self.subject.0);
        data.extend(self.public_key.as_ref());
        data
    }
}

impl<V> Inner<V> {
    pub fn new(subject: Subject, public_key: V) -> Self {
        Self {
            subject,
            public_key,
        }
    }
}

impl<V> ContextVerifier for Inner<V>
where
    V: ContextVerifier,
{
    type Context = V::Context;
    type Signature = V::Signature;
    type Error = V::Error;

    fn verify_bytes(
        &self,
        msg: &[u8],
        sig: &Self::Signature,
        context: &Self::Context,
    ) -> Result<(), Self::Error> {
        self.public_key.verify_bytes(msg, sig, context)
    }
}
