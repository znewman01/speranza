// use super::*;
use std::marker::PhantomData;

use thiserror::Error;

use super::{bundle::Bundle, Inner, Subject};
use crate::signature::ContextVerifier;
use crate::util::Canonicalize;

#[derive(Debug, Error)]
pub enum Error<E1, E2, E3> {
    #[error("certificate failed predicate: {0}")]
    Failed(#[source] E1),
    #[error("verification error (root->cert): {0}")]
    Certificate(#[source] E2),
    #[error("verification error (cert->msg): {0}")]
    Signature(#[source] E3),
}

type Predicate<V2, D, E> = dyn Fn(&Inner<V2>, &D) -> Result<(), E>;

/// Predicate verifier.
///
/// `V1` verifies the cert. `V2` verifies the signature from the key on the cert.
pub struct Verifier<V1: ContextVerifier, V2: ContextVerifier, D, E> {
    predicate: Box<Predicate<V2, D, E>>,
    _verifier: PhantomData<V1>,
}

impl<V1: ContextVerifier, V2: ContextVerifier, D, E> Verifier<V1, V2, D, E> {
    pub fn new(predicate: Box<Predicate<V2, D, E>>) -> Self {
        Self {
            predicate,
            _verifier: PhantomData,
        }
    }
}

#[derive(Debug, Error)]
#[error("subjects mismatch: expected {expected:?} got {actual:?}")]
pub struct SubjectMismatchError {
    expected: Subject,
    actual: Subject,
}

fn check_subject_match(expected: &Subject, actual: &Subject) -> Result<(), SubjectMismatchError> {
    if actual != expected {
        return Err(SubjectMismatchError {
            expected: expected.clone(),
            actual: actual.clone(),
        });
    }
    Ok(())
}

impl<V1: ContextVerifier, V2: ContextVerifier, D> Verifier<V1, V2, D, SubjectMismatchError> {
    pub fn fixed_subject(expected: Subject) -> Self {
        Self::new(Box::new(move |c, _| {
            check_subject_match(&expected, &c.subject)
        }))
    }
}

impl<V1, V2, D, E> ContextVerifier for Verifier<V1, V2, D, E>
where
    V1: ContextVerifier,
    V2: ContextVerifier,
    Inner<V2>: Canonicalize,
{
    type Context = (V2::Context, V1, V1::Context);
    type Signature = Bundle<V2, V1::Signature, D>;
    type Error = Error<E, V1::Error, V2::Error>;

    fn verify_bytes(
        &self,
        msg: &[u8],
        bundle: &Self::Signature,
        (context, root, root_context): &Self::Context,
    ) -> Result<(), Self::Error> {
        let certificate = root
            .open(&bundle.certificate, root_context)
            .map_err(Error::Certificate)?;
        (self.predicate)(certificate, &bundle.data).map_err(Error::Failed)?;
        certificate
            .verify_bytes(msg, &bundle.signature, context)
            .map_err(Error::Signature)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::certificate::{Certificate, CertificateAuthority, Ed25519Ca, FixedCertSigner};
    use crate::signature::tests::key_pairs;
    use crate::signature::ContextSigner;

    use ed25519_dalek as ed25519;
    use proptest::prelude::*;

    use std::matches;

    type Sig = ed25519::Signature;

    pub fn self_signed_certs(
    ) -> impl Strategy<Value = (Inner<ed25519::PublicKey>, ed25519::Keypair)> {
        (key_pairs(), any::<Subject>())
            .prop_map(|(key_pair, subject)| (Inner::new(subject, key_pair.public), key_pair))
    }

    #[derive(Debug)]
    pub struct RootWithChild {
        pub root: Ed25519Ca,
        pub cert: Certificate<ed25519::PublicKey, ed25519::Signature>,
        pub subject: Subject,
        pub key: ed25519::Keypair,
    }

    impl Arbitrary for RootWithChild {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            (any::<Ed25519Ca>(), any::<Subject>(), key_pairs())
                .prop_map(|(root, subject, key)| {
                    let (child, _) = root.issue(subject.clone().into(), key.public);
                    RootWithChild {
                        root,
                        cert: child,
                        subject,
                        key,
                    }
                })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn test_certificate_subject_verifier(root_with_child: RootWithChild, msg: Vec<u8>) {
            let RootWithChild { root, cert, subject, key } = root_with_child;

            let envelope = FixedCertSigner::new(&key, &cert).wrap(msg, &());
            let verifier = Verifier::fixed_subject(subject);
            let context = ((), root.verifier(), ());
            verifier.open_into(envelope, &context)?;
        }

        #[test]
        fn test_certificate_subject_verifier_bad_subject(
            root_with_child: RootWithChild,
            bad_subject: Subject,
            msg: Vec<u8>,
        ) {
            let RootWithChild { root, cert, subject, key } = root_with_child;
            prop_assume!(bad_subject != subject);

            let envelope = FixedCertSigner::new(&key, &cert).wrap(msg, &());
            let verifier = Verifier::fixed_subject(bad_subject);
            let context = ((), root.verifier(), ());
            let result = verifier.verify_envelope(&envelope, &context);
            prop_assert!(matches!(result, Err(Error::Failed(..))));
        }

        #[test]
        fn test_certificate_subject_verifier_bad_cert(
            root_with_child: RootWithChild,
            root_with_child2: RootWithChild,
            msg: Vec<u8>,
        ) {
            let RootWithChild { root, cert, subject, key } = root_with_child;
            prop_assume!(root.verifier() != root_with_child2.root.verifier());

            let envelope = FixedCertSigner::new(&key, &cert).wrap(msg, &());
            let verifier = Verifier::fixed_subject(subject);
            let context = ((), root_with_child2.root.verifier(), ());
            let result = verifier.verify_envelope(&envelope, &context);
            prop_assert!(matches!(result, Err(Error::Certificate(..))));
        }

        #[test]
        fn test_certificate_subject_verifier_bad_signature(
            root_with_child: RootWithChild,
            bad_key in key_pairs(),
            msg: Vec<u8>,
        ) {
            let RootWithChild { root, cert, subject, key } = root_with_child;
            prop_assume!(bad_key.public != key.public);

            let envelope = FixedCertSigner::new(&bad_key, &cert).wrap(msg, &());
            let verifier = Verifier::fixed_subject(subject);
            let context = ((), root.verifier(), ());
            let result = verifier.verify_envelope(&envelope, &context);
            prop_assert!(matches!(result, Err(Error::Signature(..))));
        }
    }
}
