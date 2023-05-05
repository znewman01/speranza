#[derive(Debug, Clone)]
pub struct Envelope<D, S> {
    pub data: D,
    pub signature: S,
}

impl<D, S> Envelope<D, S> {
    pub fn new(data: D, signature: S) -> Self {
        Self { data, signature }
    }
}
