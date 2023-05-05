use std::collections::HashMap;

use ed25519_dalek as ed25519;
use proptest::prelude::*;

use crate::api::{Maintainer, Package};
use crate::certificate::CertificateAuthority;
use crate::cocommitments::{CocoCa, CocoSigner};
use crate::commitments::{Evidence, Pedersen};
use crate::maps::{Map, MerkleBpt, Plain};
use crate::policy::{CocoPolicy, Policy};
use crate::repo::{Repository, SecretData};
use crate::signature::ContextSigner;

type MyPolicy<C> = CocoPolicy<C, ed25519::PublicKey, ed25519::PublicKey>;
type CocoRepository<M, C> = Repository<M, MyPolicy<C>, Evidence<C>>;

fn run_coco_test<M>(ownership: HashMap<Package, Maintainer>) -> anyhow::Result<()>
where
    M: Default + Map<Key = Package, Value = MyPolicy<Pedersen>>,
    M::VerificationError: std::error::Error + Sync + Send + 'static,
{
    let ca = CocoCa::<Pedersen>::random();
    let context = (ca.params().clone(), ((), ca.verifier(), ()));
    let mut repo = CocoRepository::<M, Pedersen>::with_context(context);
    for (package, maintainer) in &ownership {
        let (policy, comm) = MyPolicy::<Pedersen>::create(ca.params(), &maintainer.0);
        repo.register(
            package.clone(),
            policy,
            SecretData::new_with_extra(maintainer.clone(), comm),
        )?;
    }

    for (package, maintainer) in ownership {
        let msg = Vec::<u8>::from(format!("release for {package:?}"));
        // 1. Get commitment from repo.
        let comm = repo.authenticate(&maintainer, &package).cloned()?;

        // 2. Cocommitment sign:
        //    - (a) Get certificate from repo,
        //    - (b) prove commitment equality,
        //    - (c) sign the artifact.
        let key = ed25519::Keypair::generate(&mut rand::thread_rng());
        let signer = CocoSigner::try_new(&maintainer.0, &key, ca.params(), comm)?;
        let bundle = signer.sign_bytes(&msg, &ca);

        // 3. Verify.
        let digest = repo.digest();
        let proof = repo.request(&package);
        let policy = M::verify(&digest, &package, proof)?.unwrap();
        policy.verify(&msg, &bundle, repo.context())?;
    }
    Ok(())
}

proptest! {
    #[test]
    fn test_coco(ownership in prop::collection::hash_map(any::<Package>(), any::<Maintainer>(), 0..20)) {
        type InsecureMap = Plain<Package, MyPolicy<Pedersen>>;
        run_coco_test::<InsecureMap>(ownership.clone()).unwrap();

        type MerkleMap = MerkleBpt<Package, MyPolicy<Pedersen>, sha2::Sha512>;
        run_coco_test::<MerkleMap>(ownership).unwrap();
    }
}
