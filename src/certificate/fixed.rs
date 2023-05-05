use super::{Bundle, Certificate};
use crate::signature::ContextSigner;
use crate::signature::ContextVerifier;

/// Signs with a fixed certificate.
///
/// `K` is the `ContextSigner` used to sign messages. Its public key, which is
/// stored in the certificate, should be `V`. The certificate has a signature of
/// type `S`, which we mostly ignore.
pub struct FixedCertSigner<'a, K, V, S> {
    signer: &'a K,
    certificate: &'a Certificate<V, S>,
}

impl<'a, K, V, S> FixedCertSigner<'a, K, V, S> {
    pub fn new(signer: &'a K, certificate: &'a Certificate<V, S>) -> Self {
        Self {
            signer,
            certificate,
        }
    }
}

impl<'a, K, V, S> ContextSigner for FixedCertSigner<'a, K, V, S>
where
    K: ContextSigner,
    V: ContextVerifier<Signature = K::Signature>,
    Certificate<V, S>: Clone,
{
    type Context = K::Context;
    type Signature = Bundle<V, S>;

    fn sign_bytes(&self, msg: &[u8], context: &Self::Context) -> Self::Signature {
        Bundle::new(
            self.certificate.clone(),
            self.signer.sign_bytes(msg, context),
        )
    }
}
