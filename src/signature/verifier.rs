use super::Envelope;
use crate::util::Canonicalize;

pub trait ContextVerifier {
    type Context;
    type Signature;
    type Error;

    fn verify_bytes(
        &self,
        msg: &[u8],
        sig: &Self::Signature,
        context: &Self::Context,
    ) -> Result<(), Self::Error>;

    fn verify_envelope<C: Canonicalize>(
        &self,
        envelope: &Envelope<C, Self::Signature>,
        context: &Self::Context,
    ) -> Result<(), Self::Error> {
        self.verify_bytes(&envelope.data.canonicalize(), &envelope.signature, context)
    }

    fn open<'a, C: Canonicalize>(
        &self,
        envelope: &'a Envelope<C, Self::Signature>,
        context: &Self::Context,
    ) -> Result<&'a C, Self::Error> {
        self.verify_envelope(envelope, context)?;
        Ok(&envelope.data)
    }

    fn open_into<C: Canonicalize>(
        &self,
        envelope: Envelope<C, Self::Signature>,
        context: &Self::Context,
    ) -> Result<C, Self::Error> {
        self.verify_envelope(&envelope, context)?;
        Ok(envelope.data)
    }
}
