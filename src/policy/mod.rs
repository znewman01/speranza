use crate::signature::Envelope;

pub trait Policy {
    type Signature;
    type Update;
    type Context;
    type Error;

    fn verify(
        &self,
        msg: &[u8],
        signature: &Self::Signature,
        context: &Self::Context,
    ) -> Result<(), Self::Error>;

    fn update(
        &mut self,
        update: Envelope<Self::Update, Self::Signature>,
        context: &Self::Context,
    ) -> Result<(), Self::Error>;
}

mod basic;
mod cocommitments;
mod history;
mod identity;

pub use basic::{BasicPolicy, RotateVerifier};
pub use cocommitments::CocoPolicy;
pub use identity::{IdentityPolicy, RotateIdentity};
