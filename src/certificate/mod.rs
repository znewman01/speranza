use crate::signature::Envelope;

mod authority;
mod bundle;
mod data;
mod fixed;
mod predicate;
mod types;

pub use authority::{CaSigner, CertificateAuthority, Ed25519Ca};
pub use data::Inner;
pub use fixed::FixedCertSigner;
pub use predicate::{SubjectMismatchError, Verifier as PredicateVerifier};
pub use types::{Identity, Subject};
pub type Certificate<V, S> = Envelope<Inner<V>, S>;
pub type Bundle<V, S> = bundle::Bundle<V, S, ()>;
pub type FullBundle<V, S, D> = bundle::Bundle<V, S, D>;
