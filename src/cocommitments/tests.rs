use super::*;

use crate::certificate::{CertificateAuthority, Identity};
use crate::commitments::Scheme as _;
use crate::signature::tests::key_pairs;
use crate::signature::{ContextSigner, ContextVerifier};
use crate::util::Canonicalize;
use proptest::prelude::*;

type Scheme = crate::commitments::Pedersen;
type Sig = ed25519_dalek::Signature;

proptest! {
    #[test]
    fn test_coco(
        ca: CocoCa<Scheme>,
        subject: Identity,
        key in key_pairs(),
        msg: Vec<u8>
    ) {
        let mut rng = rand::thread_rng();

        let params = ca.params();
        let (c1, r1) = params.commit(&subject.canonicalize(), &mut rng);

        let verifier = coco_verifier(params.clone(), c1);

        let signer = CocoSigner::try_new(&subject, &key, params, (c1, r1))?;
        let bundle = signer.sign_bytes(&msg, &ca);
        let context = ((), ca.verifier(), ());
        verifier.verify_bytes(&msg, &bundle, &context)?;
    }
}
