use super::Envelope;
use crate::util::Canonicalize;

pub trait ContextSigner {
    type Context;
    type Signature;

    fn sign_bytes(&self, msg: &[u8], context: &Self::Context) -> Self::Signature;

    fn wrap<C: Canonicalize>(
        &self,
        data: C,
        context: &Self::Context,
    ) -> Envelope<C, Self::Signature> {
        let signature = self.sign_bytes(&data.canonicalize(), context);
        Envelope::new(data, signature)
    }
}
