use proptest::prelude::*;

pub fn insertions<K, V>() -> impl Strategy<Value = Vec<(K, V)>>
where
    K: Arbitrary,
    V: Arbitrary,
{
    prop::collection::vec((any::<K>(), any::<V>()), 0..20)
}

#[cfg(test)]
macro_rules! check_map {
    ($type:ty) => {
        /// Property tests that $type is a maps::Map.
        mod map_properties {
            #![allow(unused_imports)]
            use std::collections::HashMap;

            use proptest::prelude::*;

            use super::*;
            use crate::maps::tests::insertions;
            use crate::maps::Map;

            type Key = <$type as Map>::Key;
            type Value = <$type as Map>::Value;

            proptest! {
                /// Tests that, after a sequence of insertions, the proof is valid and the result is correct.
                #[test]
                fn test_map(insertions in insertions::<Key, Value>(), key: Key) {
                    let mut map: $type = Default::default();
                    // Use a hash map as a reference for the expected result after the given insertions.
                    let mut reference = HashMap::<Key, Value>::default();

                    for (key, value) in insertions {
                        map.insert(key.clone(), value.clone());
                        reference.insert(key, value);
                    }

                    let digest = map.digest();
                    let proof = map.lookup(&key).clone();
                    assert_eq!(
                        <$type as Map>::verify(&digest, &key, proof),
                        Ok(reference.get(&key).cloned())
                    );
                }
            }
        }
    };
}

#[cfg(test)]
pub(crate) use check_map;
