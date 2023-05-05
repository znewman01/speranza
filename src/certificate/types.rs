#[cfg(test)]
use proptest_derive::Arbitrary;

use crate::util::Canonicalize;

#[cfg_attr(test, derive(Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject(pub Vec<u8>);

impl Canonicalize for Subject {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("Subject:");
        data.extend_from_slice(&self.0);
        data
    }
}

#[cfg_attr(test, derive(Arbitrary))]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Identity(pub Vec<u8>);

impl From<Identity> for Subject {
    fn from(identity: Identity) -> Self {
        Subject(identity.0)
    }
}

impl From<Subject> for Identity {
    fn from(subject: Subject) -> Self {
        Identity(subject.0)
    }
}

impl Canonicalize for Identity {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("Identity:");
        data.extend_from_slice(&self.0);
        data
    }
}
