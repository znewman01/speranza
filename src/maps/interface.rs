use std::fmt::Debug;
use std::hash::Hash;

use crate::{Identity, Maintainer, Package};

/// Authenticated map.
pub trait Map {
    type Key: Hash + Eq;
    type Value: Debug;
    type Digest;
    type LookupProof;
    type VerificationError;

    fn digest(&self) -> Self::Digest;
    fn lookup(&self, key: &Self::Key) -> Self::LookupProof;
    fn insert(&mut self, key: Self::Key, value: Self::Value);
    fn lookup_unchecked(&self, key: &Self::Key) -> Option<&Self::Value>;

    fn verify(
        digest: &Self::Digest,
        key: &Self::Key,
        result: Self::LookupProof,
    ) -> Result<Option<Self::Value>, Self::VerificationError>;
}

pub fn with_dummy_data<M>(size: u64) -> M
where
    M: Map<Key = Package, Value = Maintainer> + Default,
{
    let mut map = M::default();
    for i in 0..size {
        map.insert(
            Package(format!("package{i}").into()),
            Maintainer(Identity(format!("maintainer{i}").into())),
        );
    }
    map
}
