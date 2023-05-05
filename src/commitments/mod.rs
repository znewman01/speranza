mod insecure;
mod pedersen;
mod scheme;

#[cfg(test)]
pub(crate) use scheme::check_commitment;
pub use scheme::{Evidence, Scheme};
pub type Pedersen = pedersen::Parameters<sha2::Sha512>;
pub type Insecure = insecure::Parameters;
