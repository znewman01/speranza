use std::fmt::Debug;

use derivative::Derivative;

use super::Certificate;
use crate::signature::ContextVerifier;

/// A signature along with its accompanying certificate.
///
/// The signature is of the type verified by public key `K` in the certificate.
/// The certificate itself is signed (with a signature of type `S`).
#[derive(Derivative)]
#[derivative(Debug(bound = "D: Debug, Certificate<V, S>: Debug, V::Signature: Debug"))]
pub struct Bundle<V: ContextVerifier, S, D> {
    pub certificate: Certificate<V, S>, // TODO: Could be a chain of certificates.
    pub signature: V::Signature,
    pub data: D,
}

impl<V: ContextVerifier, S, D: Default> Bundle<V, S, D> {
    pub fn new(certificate: Certificate<V, S>, signature: V::Signature) -> Self {
        Bundle {
            certificate,
            signature,
            data: Default::default(),
        }
    }
}

impl<V: ContextVerifier, S, D> Bundle<V, S, D> {
    pub fn new_with_extra(
        certificate: Certificate<V, S>,
        signature: V::Signature,
        data: D,
    ) -> Self {
        Bundle {
            certificate,
            signature,
            data,
        }
    }

    pub fn replace_extra_data<D2>(self, data: D2) -> Bundle<V, S, D2> {
        Bundle {
            certificate: self.certificate,
            signature: self.signature,
            data,
        }
    }
}
