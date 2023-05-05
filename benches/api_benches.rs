use std::fmt::Debug;

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode,
    Throughput,
};
use ed25519_dalek as ed25519;
use rand::Rng;

use speranza::*;

fn sizes() -> Vec<u64> {
    vec![10000u64, 31622, 100000, 316227, 1000000, 3162277]
}

pub fn bench_signing(c: &mut Criterion) {
    let rng = &mut rand::thread_rng();
    let key = ed25519::Keypair::generate(rng);
    let msg = "the message".as_bytes();
    c.bench_function(&"ed25519-sign", |b| {
        b.iter(|| key.sign_bytes(&black_box(msg), &()))
    });

    let sig = key.sign_bytes(&black_box(msg), &());
    c.bench_function(&"ed25519-verify", |b| {
        b.iter(|| key.verify(black_box(msg), &sig))
    });
}

/// Benchmarks for *just* (co)-commitments: Pedersen operations, along with
/// Pedersen + signing/verifying.
pub fn bench_commitments(c: &mut Criterion) {
    let rng = &mut rand::thread_rng();

    let identity = Identity("user@example.com".into());
    let ca = CocoCa::<Pedersen>::random();
    let key = ed25519::Keypair::generate(rng);
    let (policy, comm) = CocoPolicy::create(ca.params(), &identity);
    let signer = CocoSigner::try_new(&identity, &key, ca.params(), comm).unwrap();
    let msg = "the message".as_bytes();

    c.bench_function(&"pedersen-commit", |b| {
        b.iter(|| ca.params().commit(black_box(msg), rng))
    });

    let evidence = ca.params().commit(msg, rng);
    c.bench_function(&"pedersen-commit-verify", |b| {
        b.iter(|| ca.params().verify(black_box(msg), &evidence.0, &evidence.1))
    });

    let comm1 = ca.params().commit(msg, &mut rand::thread_rng());
    let comm2 = ca.params().commit(msg, &mut rand::thread_rng());
    c.bench_function(&"pedersen-prove-equality", |b| {
        b.iter(|| ca.params().prove_equality(msg, &comm1, &comm2, rng))
    });

    let comm1 = ca.params().commit(msg, rng);
    let comm2 = ca.params().commit(msg, rng);
    let proof = ca.params().prove_equality(msg, &comm1, &comm2, rng);
    c.bench_function(&"pedersen-prove-equality-verify", |b| {
        b.iter(|| ca.params().verify_equality(&comm1.0, &comm2.0, &proof))
    });

    c.bench_function(&"policy-sign", |b| {
        b.iter(|| signer.sign_bytes(black_box(msg), &ca))
    });

    let bundle = signer.sign_bytes(msg, &ca);
    let context = (ca.params().clone(), ((), ca.verifier(), ()));
    c.bench_function(&"policy-verify", |b| {
        b.iter(|| policy.verify(black_box(msg), &bundle, &context))
    });
}

type MyMerkle = MerkleBpt<Package, Maintainer, sha2::Sha512>;
type MyPolicy<C> = CocoPolicy<C, ed25519::PublicKey, ed25519::PublicKey>;
type MyPolicyMerkle<C> = MerkleBpt<Package, MyPolicy<C>, sha2::Sha512>;
type CocoRepository<M, C> = Repository<M, MyPolicy<C>, Evidence<C>>;
type MerkleRepository = CocoRepository<MyPolicyMerkle<Pedersen>, Pedersen>;

fn run_bench<M>(c: &mut Criterion, method: &str)
where
    M: Clone,
    M: Map<Key = Package, Value = Maintainer> + Default,
    M::VerificationError: Debug,
    M::LookupProof: Clone,
{
    let mut group = c.benchmark_group(method);
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    let mut rng = rand::thread_rng();

    for size in sizes() {
        group.throughput(Throughput::Elements(size));

        // 1. Making tree
        group.bench_with_input(BenchmarkId::new("make-tree", size), &size, |b, &size| {
            b.iter(|| map_with_dummy_data::<M>(size));
        });

        let map = map_with_dummy_data::<M>(size);
        let package = Package(format!("package{}", rng.gen_range(0, size)).into());
        group.bench_with_input(BenchmarkId::new("lookup", size), &size, |b, &_size| {
            b.iter(|| map.lookup(&package));
        });

        let package = Package(format!("package{}", rng.gen_range(0, size)).into());
        let digest = map.digest();
        let proof = map.lookup(&package);
        group.bench_with_input(BenchmarkId::new("verify", size), &size, |b, &_size| {
            b.iter(|| {
                let _ = M::verify(&digest, &package, proof.clone()).unwrap();
            })
        });

        let mut packages = vec![];
        let mut maintainers = vec![];
        for _ in 0..10000 {
            packages.push(Package(
                format!("new package{}", rng.gen_range(0, size)).into(),
            ));
            maintainers.push(Maintainer(Identity(
                format!("new maintainer{}", rng.gen_range(0, size)).into(),
            )));
        }
        group.bench_with_input(BenchmarkId::new("insert", size), &size, |b, &_size| {
            b.iter_batched(
                || (map.clone(), packages.clone(), maintainers.clone()),
                |(mut map, packages, maintainers)| {
                    for (package, maintainer) in packages.into_iter().zip(maintainers.into_iter()) {
                        map.insert(package, maintainer);
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}
pub fn bench_map(c: &mut Criterion) {
    run_bench::<MyMerkle>(c, "merkle");
    run_bench::<PlainMap<Package, Maintainer>>(c, "plain");
}

fn prep_repo(size: u64) -> (MerkleRepository, CocoCa<Pedersen>) {
    let ca = CocoCa::<Pedersen>::random();
    let context = (ca.params().clone(), ((), ca.verifier(), ()));

    let mut repo = MerkleRepository::with_context(context);
    for i in 0..size {
        let package = Package(format!("package{}", i).into());
        let maintainer = Maintainer(Identity(format!("maintainer{}", i).into()));
        let (policy, comm) = MyPolicy::<Pedersen>::create(ca.params(), &maintainer.0);
        repo.register(
            package.clone(),
            policy,
            SecretData::new_with_extra(maintainer.clone(), comm),
        )
        .unwrap();
    }
    (repo, ca)
}

pub fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end-to-end");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    let mut rng = rand::thread_rng();
    let msg = "the message".as_bytes();

    for size in sizes() {
        group.throughput(Throughput::Elements(size));

        let (repo, ca) = prep_repo(size);

        let i = rng.gen_range(0, size);
        let package = Package(format!("package{}", i).into());
        let maintainer = Maintainer(Identity(format!("maintainer{}", i).into()));
        group.bench_with_input(BenchmarkId::new("sign", size), &size, |b, &_size| {
            b.iter(|| {
                let comm = repo.authenticate(&maintainer, &package).cloned().unwrap();
                let key = ed25519::Keypair::generate(&mut rand::thread_rng());
                let signer = CocoSigner::try_new(&maintainer.0, &key, ca.params(), comm).unwrap();
                repo.request(black_box(&package));
                signer.sign_bytes(&black_box(msg), &ca);
            })
        });

        let i = rng.gen_range(0, size);
        let package = Package(format!("package{}", i).into());
        let maintainer = Maintainer(Identity(format!("maintainer{}", i).into()));
        let comm = repo.authenticate(&maintainer, &package).cloned().unwrap();
        let key = ed25519::Keypair::generate(&mut rand::thread_rng());
        let signer = CocoSigner::try_new(&maintainer.0, &key, ca.params(), comm).unwrap();
        let proof = repo.request(&package);
        let bundle = signer.sign_bytes(&msg, &ca);
        group.bench_with_input(BenchmarkId::new("verify", size), &size, |b, &_size| {
            b.iter(|| {
                let digest = repo.digest();
                let policy = MyPolicyMerkle::verify(&digest, &package, proof.clone())
                    .unwrap()
                    .unwrap();
                policy.verify(&msg, &bundle, repo.context()).unwrap();
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_signing,
    bench_commitments,
    bench_map,
    bench_end_to_end
);
criterion_main!(benches);
