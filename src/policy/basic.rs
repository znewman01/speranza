use crate::signature::{ContextSigner, ContextVerifier, Envelope};
use crate::util::Canonicalize;

use super::Policy;
use ed25519_dalek as ed25519;

/// The simplest possible policy: one fixed verifier at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicPolicy<V> {
    key: V,
}

impl<V> From<V> for BasicPolicy<V> {
    fn from(key: V) -> Self {
        Self { key }
    }
}

#[derive(Debug, Clone)]
pub struct RotateVerifierInner<V>(V);

impl<K: Canonicalize> Canonicalize for RotateVerifierInner<K> {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("RotateVerifierInner:");
        data.extend(self.0.canonicalize());
        data
    }
}

pub type RotateVerifier<V> = Envelope<RotateVerifierInner<V>, <V as ContextVerifier>::Signature>;

impl RotateVerifier<ed25519::PublicKey> {
    pub fn make(old: &ed25519::Keypair, new: &ed25519::Keypair) -> Self {
        old.wrap(RotateVerifierInner(new.public), &())
    }
}

impl<V> Policy for BasicPolicy<V>
where
    V: ContextVerifier,
    RotateVerifierInner<V>: Canonicalize,
{
    type Signature = V::Signature;
    type Update = RotateVerifierInner<V>;
    type Context = V::Context;
    type Error = V::Error;

    fn update(
        &mut self,
        update: RotateVerifier<V>,
        context: &Self::Context,
    ) -> Result<(), Self::Error> {
        self.key = self.key.open_into(update, context)?.0;
        Ok(())
    }

    fn verify(
        &self,
        msg: &[u8],
        signature: &Self::Signature,
        context: &Self::Context,
    ) -> Result<(), Self::Error> {
        self.key.verify_bytes(msg, signature, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tests::key_pairs;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_basic_policy(key_pair in key_pairs(), msg: Vec<u8>) {
            let policy = BasicPolicy::from(key_pair.public);
            let signature = key_pair.sign_bytes(&msg, &());
            policy.verify(&msg, &signature, &())?;
        }

        #[test]
        fn test_basic_policy_bad_signature(
            key_pair in key_pairs(),
            bad_key_pair in key_pairs(),
            msg: Vec<u8>
        ) {
            prop_assume!(bad_key_pair.public != key_pair.public);
            let policy = BasicPolicy::from(key_pair.public);
            let bad_signature = bad_key_pair.sign_bytes(&msg, &());
            prop_assert!(policy.verify(&msg, &bad_signature, &()).is_err());
        }

        #[test]
        fn test_basic_policy_update(
            initial in key_pairs(),
            updates in prop::collection::vec(key_pairs(), 1..10),
            msg: Vec<u8>
        ) {
            let mut policy = BasicPolicy::from(initial.public);

            let mut current = initial;
            for update in updates {
                let old_signature = current.sign_bytes(&msg, &());
                prop_assert!(policy.verify(&msg, &old_signature, &()).is_ok());

                policy.update(RotateVerifier::make(&current, &update), &())?;

                let new_signature = update.sign_bytes(&msg, &());
                prop_assert!(policy.verify(&msg, &new_signature, &()).is_ok());
                if current.public != update.public {
                prop_assert!(policy.verify(&msg, &old_signature, &()).is_err());
                }

                current = update;
            }

        }
    }
}
