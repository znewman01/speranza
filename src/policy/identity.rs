use std::marker::PhantomData;

use super::*;
use crate::{
    certificate::{Identity, PredicateVerifier, SubjectMismatchError},
    signature::ContextVerifier,
    util::Canonicalize,
};

/// A policy checking that certifiates are signed by a global root (the context)
/// and matching a given identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPolicy<V1, V2> {
    expected: Identity,
    _v1: PhantomData<V1>,
    _v2: PhantomData<V2>,
}

impl<V1, V2> From<Identity> for IdentityPolicy<V1, V2> {
    fn from(identity: Identity) -> Self {
        Self {
            expected: identity,
            _v1: PhantomData,
            _v2: PhantomData,
        }
    }
}

type SubjectVerifier<V1, V2> = PredicateVerifier<V1, V2, (), SubjectMismatchError>;

impl<V1, V2> IdentityPolicy<V1, V2>
where
    V1: ContextVerifier,
    V2: ContextVerifier,
    SubjectVerifier<V1, V2>: ContextVerifier,
{
    fn verifier(&self) -> SubjectVerifier<V1, V2> {
        PredicateVerifier::fixed_subject(self.expected.clone().into())
    }
}

#[derive(Debug, Clone)]
pub struct RotateIdentityInner(Identity);

impl Canonicalize for RotateIdentityInner {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("RotateIdentityInner:");
        data.extend(self.0.canonicalize());
        data
    }
}

pub type RotateIdentity<V> = Envelope<RotateIdentityInner, <V as ContextVerifier>::Signature>;

impl<V1, V2> Policy for IdentityPolicy<V1, V2>
where
    V1: ContextVerifier,
    V2: ContextVerifier,
    SubjectVerifier<V1, V2>: ContextVerifier,
{
    type Signature = <SubjectVerifier<V1, V2> as ContextVerifier>::Signature;
    type Update = RotateIdentityInner;
    type Context = <SubjectVerifier<V1, V2> as ContextVerifier>::Context;
    type Error = <SubjectVerifier<V1, V2> as ContextVerifier>::Error;

    fn verify(
        &self,
        msg: &[u8],
        signature: &Self::Signature,
        context: &Self::Context,
    ) -> Result<(), Self::Error> {
        let verifier = self.verifier();
        verifier.verify_bytes(msg, signature, context)
    }

    fn update(
        &mut self,
        update: Envelope<Self::Update, Self::Signature>,
        context: &Self::Context,
    ) -> Result<(), Self::Error> {
        let verifier = self.verifier();
        let inner = verifier.open_into(update, context)?;
        self.expected = inner.0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{Bundle, CertificateAuthority, Ed25519Ca, FixedCertSigner, Identity};
    use crate::signature::tests::key_pairs;
    use crate::signature::ContextSigner;
    use ed25519_dalek as ed25519;
    use proptest::prelude::*;

    fn sign_it(
        ca: &Ed25519Ca,
        key: &ed25519::Keypair,
        identity: Identity,
        msg: &[u8],
    ) -> Bundle<ed25519::PublicKey, ed25519::Signature> {
        let (cert, _) = ca.issue(identity, key.public);
        let signer = FixedCertSigner::new(key, &cert);
        signer.sign_bytes(&msg, &())
    }

    proptest! {
        #[test]
        fn test_certificate_subject_policy(
            ca: Ed25519Ca,
            (initial, key) in (any::<Identity>(), key_pairs()),
            msg: Vec<u8>
        ) {
            let policy = IdentityPolicy::from(initial.clone());
            let bundle = sign_it(&ca, &key, initial.clone(), &msg);
            let context = ((), ca.verifier(), ());
            policy.verify(&msg, &bundle, &context)?;
        }

        #[test]
        fn test_basic_policy_bad_signature(
            ca: Ed25519Ca,
            (initial, key) in (any::<Identity>(), key_pairs()),
            bad_key in key_pairs(),
            msg: Vec<u8>
        ) {
            prop_assume!(bad_key.public != key.public);
            let policy = IdentityPolicy::from(initial.clone());
            let (cert, _) = ca.issue(initial, key.public);
            let signer = FixedCertSigner::new(&bad_key, &cert);
            let bundle = signer.sign_bytes(&msg, &());
            let context = ((), ca.verifier(), ());
            prop_assert!(policy.verify(&msg, &bundle, &context).is_err());
        }

        #[test]
        fn test_basic_policy_update(
            ca: Ed25519Ca,
            (initial, key) in (any::<Identity>(), key_pairs()),
            updates in prop::collection::vec((any::<Identity>(), key_pairs()), 1..10),
            msg: Vec<u8>
        ) {
            let mut policy = IdentityPolicy::from(initial.clone());
            let context = ((), ca.verifier(), ());

            let bundle = sign_it(&ca, &key, initial.clone(), &msg);
            policy.verify(&msg, &bundle, &context)?;

            let mut old_identity = initial;
            let mut old_key = key;
            for (new_identity, new_key) in updates {
                let old_bundle = sign_it(&ca, &old_key, old_identity.clone(), &msg);
                policy.verify(&msg, &old_bundle, &context)?;

                let update_inner = RotateIdentityInner(new_identity.clone());
                let signature = sign_it(&ca, &old_key, old_identity.clone(), &update_inner.canonicalize());
                let update = RotateIdentity::<SubjectVerifier<ed25519::PublicKey, ed25519::PublicKey>>::new(update_inner, signature);
                policy.update(update, &context)?;

                let new_bundle = sign_it(&ca, &new_key, new_identity.clone(), &msg);
                policy.verify(&msg, &new_bundle, &context)?;
                if old_identity != new_identity {
                  prop_assert!(policy.verify(&msg, &old_bundle, &context).is_err());
                }

                old_identity = new_identity;
                old_key = new_key;
            }

        }

    }
}
