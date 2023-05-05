use std::collections::HashMap;

use thiserror::Error;

use crate::api::{Maintainer, Package};
use crate::maps::Map;
use crate::policy::Policy;

/// This stores data that should be kept secret to the Repository.
pub struct SecretData<E> {
    /// The cleartext identity of the maintainer.
    maintainer: Maintainer,
    extra: E,
}

impl<E: Default> SecretData<E> {
    pub fn new(maintainer: Maintainer) -> Self {
        Self {
            maintainer,
            extra: Default::default(),
        }
    }
}

impl<E> SecretData<E> {
    pub fn new_with_extra(maintainer: Maintainer, extra: E) -> Self {
        Self { maintainer, extra }
    }
}

pub struct Repository<M, P: Policy, E> {
    /// Authenticated map from Package -> Policy
    maintainer_map: M,
    secret_map: HashMap<Package, SecretData<E>>,
    context: P::Context,
}

#[derive(Debug, Error)]
#[error("auth failed for {maintainer:?} as {package:?}")]
pub struct AuthError {
    maintainer: Maintainer,
    package: Package,
}

#[derive(Debug, Error)]
#[error("package {0:?} already registered")]
pub struct AlreadyRegisteredError(Package);

impl<M, P, E> Repository<M, P, E>
where
    P: Policy,
    P::Context: Default,
    M: Default,
{
    pub fn empty() -> Self {
        Self::with_context(Default::default())
    }
}

impl<M, P, E> Repository<M, P, E>
where
    P: Policy,
    M: Default,
{
    pub fn with_context(context: P::Context) -> Self {
        Self {
            maintainer_map: Default::default(),
            secret_map: Default::default(),
            context,
        }
    }
}

impl<M, P, E> Repository<M, P, E>
where
    P: Policy,
    M: Map<Key = Package, Value = P>,
{
    pub fn authenticate(
        &self,
        maintainer: &Maintainer,
        package: &Package,
    ) -> Result<&E, AuthError> {
        let secret_data = self.secret_map.get(package).ok_or_else(|| AuthError {
            maintainer: maintainer.clone(),
            package: package.clone(),
        })?;
        if maintainer != &secret_data.maintainer {
            return Err(AuthError {
                maintainer: maintainer.clone(),
                package: package.clone(),
            });
        }
        Ok(&secret_data.extra)
    }

    pub fn register(
        &mut self,
        package: Package,
        initial_policy: P,
        secret_data: SecretData<E>,
    ) -> Result<(), AlreadyRegisteredError> {
        if self.maintainer_map.lookup_unchecked(&package).is_some() {
            return Err(AlreadyRegisteredError(package));
        }
        debug_assert!(self.secret_map.get(&package).is_none());

        self.maintainer_map.insert(package.clone(), initial_policy);
        self.secret_map.insert(package, secret_data);
        Ok(())
    }

    pub fn digest(&self) -> M::Digest {
        self.maintainer_map.digest()
    }

    pub fn request(&self, package: &Package) -> M::LookupProof {
        self.maintainer_map.lookup(package)
    }

    pub fn context(&self) -> &P::Context {
        &self.context
    }
}
