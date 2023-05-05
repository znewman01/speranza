use std::io;

use speranza::{Identity, Maintainer, Map, MerkleBpt, Package, PlainMap, SizedBytes};

fn prep_map<M: Map + Default>(size: u64) -> (M, Package)
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
    let package = Package(format!("package{}", size / 2).into());
    (map, package)
}

type MerkleMap = MerkleBpt<Package, Maintainer, sha2::Sha512>;

#[derive(Debug)]
struct Record {
    method: String,
    num_packages: u64,
    initial_fetch_bytes: usize,
    proof_size_bytes: usize,
    map_size_bytes: usize,
}

impl Record {
    fn print_csv_header<W: io::Write>(out: &mut W) {
        writeln!(
            out,
            "method,num_packages,initial_fetch_bytes,proof_size_bytes,map_size_bytes"
        )
        .unwrap();
    }

    fn print_csv<W: io::Write>(&self, out: &mut W) {
        writeln!(
            out,
            "{},{},{},{},{}",
            self.method,
            self.num_packages,
            self.initial_fetch_bytes,
            self.proof_size_bytes,
            self.map_size_bytes
        )
        .unwrap();
    }
}

fn measure<M>(method: &str, size: u64) -> Record
where
    M: Map<Key = Package, Value = Maintainer> + Default + SizedBytes,
    <M as Map>::Digest: SizedBytes,
    <M as Map>::LookupProof: SizedBytes,
{
    let (map, package) = prep_map::<M>(size);
    Record {
        method: method.to_string(),
        num_packages: size,
        initial_fetch_bytes: map.digest().size_bytes(),
        proof_size_bytes: map.lookup(&package).size_bytes(),
        map_size_bytes: map.size_bytes(),
    }
}

fn main() {
    let mut out = io::stdout();
    Record::print_csv_header(&mut out);
    for exponent in 0..8 {
        let size = 10u64.pow(exponent);

        measure::<MerkleMap>("merkle", size).print_csv(&mut out);
        measure::<PlainMap<Package, Maintainer>>("plain", size).print_csv(&mut out);
    }
}
