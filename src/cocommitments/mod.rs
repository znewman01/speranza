use ed25519_dalek as ed25519;

use crate::certificate::FullBundle;
use crate::commitments::Scheme;

mod ca;
mod signer;
mod verifier;

pub use ca::CocoCa;
pub use signer::CocoSigner;
pub use verifier::{coco_verifier, Error as CocoVerifyError};

pub type Bundle<C> =
    FullBundle<ed25519::PublicKey, ed25519::Signature, <C as Scheme>::EqualityProof>;

#[cfg(test)]
mod tests;
