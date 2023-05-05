use std::fmt::Debug;
use std::hash::Hash;
use std::{collections::HashMap, convert::Infallible};

use derivative::Derivative;

use crate::util::SizedBytes;

use super::Map;

#[derive(Clone, Debug, Derivative)]
#[derivative(Default(bound = ""))]
pub struct Insecure<K, V>(HashMap<K, V>);

impl<K, V> SizedBytes for Insecure<K, V>
where
    K: SizedBytes,
    V: SizedBytes,
{
    fn size_bytes(&self) -> usize {
        self.0
            .iter()
            .map(|(k, v)| k.size_bytes() + v.size_bytes())
            .sum()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LookupProof;

impl SizedBytes for LookupProof {
    fn size_bytes(&self) -> usize {
        0
    }
}

impl<K, V> Map for Insecure<K, V>
where
    K: Clone + Hash + Eq,
    V: Clone + Debug,
{
    type Key = K;
    type Value = V;
    type Digest = Self;
    type LookupProof = LookupProof;
    type VerificationError = Infallible;

    fn digest(&self) -> Self::Digest {
        self.clone()
    }

    fn lookup(&self, _: &Self::Key) -> Self::LookupProof {
        LookupProof
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        self.0.insert(key, value);
    }

    fn verify(
        digest: &Self::Digest,
        key: &Self::Key,
        _: Self::LookupProof,
    ) -> Result<Option<Self::Value>, Self::VerificationError> {
        Ok(digest.0.get(key).cloned())
    }

    fn lookup_unchecked(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.0.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::tests::check_map;

    check_map!(Insecure<u8, u8>);
}
