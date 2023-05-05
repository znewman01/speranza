#[cfg(test)]
use proptest_derive::Arbitrary;

use crate::{certificate::Identity, util::Canonicalize, SizedBytes};

#[cfg_attr(test, derive(Arbitrary))]
// A cleartext maintainer identity.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Maintainer(pub Identity);

impl Canonicalize for Maintainer {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("Maintainer:");
        data.extend_from_slice(&self.0.canonicalize());
        data
    }
}

impl SizedBytes for Maintainer {
    fn size_bytes(&self) -> usize {
        self.0 .0.len()
    }
}

#[cfg_attr(test, derive(Arbitrary))]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Package(pub String);

impl Canonicalize for Package {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("Maintainer:");
        data.extend_from_slice(self.0.as_bytes());
        data
    }
}

impl SizedBytes for Package {
    fn size_bytes(&self) -> usize {
        self.0.len()
    }
}
