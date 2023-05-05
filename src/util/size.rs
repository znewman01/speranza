pub trait SizedBytes {
    fn size_bytes(&self) -> usize;
}

pub trait FixedSizedBytes {
    fn fixed_size_bytes() -> usize;
}

impl<T: FixedSizedBytes> SizedBytes for T {
    fn size_bytes(&self) -> usize {
        T::fixed_size_bytes()
    }
}
