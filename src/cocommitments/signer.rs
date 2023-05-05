use std::fmt::Debug;

use derivative::Derivative;
use ed25519_dalek as ed25519;
use thiserror::Error;

use super::CocoCa;
use crate::certificate::{Bundle as CertificateBundle, FullBundle};
use crate::certificate::{CertificateAuthority, FixedCertSigner, Identity};
use crate::commitments::{Evidence, Scheme};
use crate::signature::ContextSigner;
use crate::util::Canonicalize;

#[derive(Derivative)]
#[derivative(Debug(bound = "Evidence<C>: Debug"))]
pub struct CocoSigner<'a, C: Scheme> {
    cleartext: &'a Identity,
    key: &'a ed25519::Keypair,
    comm: Evidence<C>,
}

#[derive(Debug, Error)]
#[error("commitment didn't verify")]
pub struct Error;

impl<'a, C: Scheme> CocoSigner<'a, C> {
    pub fn try_new(
        cleartext: &'a Identity,
        key: &'a ed25519::Keypair,
        params: &C,
        comm: Evidence<C>,
    ) -> Result<Self, Error> {
        if !params.verify(&cleartext.canonicalize(), &comm.0, &comm.1) {
            return Err(Error);
        }
        Ok(Self {
            cleartext,
            key,
            comm,
        })
    }
}

impl<'a, C: Scheme> ContextSigner for CocoSigner<'a, C>
where
    CocoCa<C>: CertificateAuthority<ExtraResponse = Evidence<C>, Verifier = ed25519::PublicKey>,
    for<'b> FixedCertSigner<'b, ed25519::Keypair, ed25519::PublicKey, ed25519::Signature>:
        ContextSigner<
            Context = (),
            Signature = CertificateBundle<ed25519::PublicKey, ed25519::Signature>,
        >,
{
    type Context = CocoCa<C>;
    type Signature = FullBundle<ed25519::PublicKey, ed25519::Signature, C::EqualityProof>;

    fn sign_bytes(&self, msg: &[u8], ca: &Self::Context) -> Self::Signature {
        let mut rng = rand::thread_rng();
        let (cert, comm2) = ca.issue(self.cleartext.clone(), self.key.public);
        let proof = ca.params().prove_equality(
            &self.cleartext.canonicalize(),
            &self.comm,
            &comm2,
            &mut rng,
        );
        FixedCertSigner::new(self.key, &cert)
            .sign_bytes(msg, &())
            .replace_extra_data(proof)
    }
}
