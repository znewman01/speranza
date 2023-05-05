use super::ContextSigner;
use super::ContextVerifier;
use ed25519_dalek as ed25519;

impl ContextSigner for ed25519::Keypair {
    type Context = ();
    type Signature = ed25519::Signature;

    fn sign_bytes(&self, msg: &[u8], _: &Self::Context) -> Self::Signature {
        use ::signature::Signer as _;
        self.sign(msg)
    }
}

impl ContextVerifier for ed25519::PublicKey {
    type Context = ();
    type Signature = ed25519::Signature;
    type Error = ::signature::Error;

    fn verify_bytes(
        &self,
        msg: &[u8],
        sig: &Self::Signature,
        _: &Self::Context,
    ) -> Result<(), Self::Error> {
        use ::signature::Verifier as _;
        self.verify(msg, sig)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;

    pub fn key_pairs() -> impl Strategy<Value = ed25519_dalek::Keypair> {
        any::<[u8; 32]>()
            .prop_map(|bytes| ed25519_dalek::SecretKey::from_bytes(&bytes).expect("correct length"))
            .prop_map(|sk| {
                let public = (&sk).into();
                ed25519_dalek::Keypair { secret: sk, public }
            })
    }

    proptest! {
        #[test]
        fn test_fixed_keys(key in key_pairs(), msg: Vec<u8>) {
            let signature = key.sign_bytes(&msg, &());
            key.public.verify_bytes(&msg, &signature, &())?;
        }
    }
}
