use digest::{Digest as Hasher, Output};
use ed25519_dalek as ed25519;

pub trait Canonicalize {
    // TODO: probably shouldn't allocate
    fn canonicalize(&self) -> Vec<u8>;
}

impl Canonicalize for Vec<u8> {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("Vec<u8>:");
        data.extend_from_slice(self);
        data
    }
}

impl Canonicalize for u8 {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("u8:");
        data.push(*self);
        data
    }
}

impl Canonicalize for ed25519::PublicKey {
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("ed25519_dalek PublicKey:");
        data.extend_from_slice(self.as_bytes());
        data
    }
}

pub fn hash<D: Canonicalize, H: Hasher>(data: &D) -> Output<H> {
    let mut hasher = H::new();
    hasher.update(data.canonicalize());
    hasher.finalize()
}
