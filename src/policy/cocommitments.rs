use std::marker::PhantomData;

use super::Policy;
use crate::certificate::{Identity, Inner as CertificateInner, PredicateVerifier};
use crate::cocommitments::{coco_verifier, Bundle, CocoVerifyError};
use crate::commitments::{Evidence, Scheme};
use crate::signature::{ContextVerifier, Envelope};
use crate::util::Canonicalize;

#[derive(Debug, Clone)]
pub struct CocoPolicy<C: Scheme, V1, V2> {
    c: C::Commitment,
    _v1: PhantomData<V1>,
    _v2: PhantomData<V2>,
}

impl<C: Scheme, V1, V2> CocoPolicy<C, V1, V2>
where
    C::Commitment: Clone,
{
    pub fn create(params: &C, identity: &Identity) -> (Self, Evidence<C>) {
        let (c, r) = params.commit(&identity.canonicalize(), &mut rand::thread_rng());
        let policy = Self {
            c: c.clone(),
            _v1: PhantomData,
            _v2: PhantomData,
        };
        (policy, (c, r))
    }

    pub fn from_commitment(c: C::Commitment) -> Self {
        Self {
            c,
            _v1: PhantomData,
            _v2: PhantomData,
        }
    }
}

impl<C, V1, V2> Canonicalize for CocoPolicy<C, V1, V2>
where
    C: Scheme,
    C::Commitment: Canonicalize,
{
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::from("CocoPolicy:");
        data.extend_from_slice(&self.c.canonicalize());
        data
    }
}

type SubjectVerifier<C, V1, V2> = PredicateVerifier<
    V1,
    V2,
    <C as Scheme>::EqualityProof,
    CocoVerifyError<<<C as Scheme>::Commitment as TryFrom<Vec<u8>>>::Error>,
>;

#[derive(Debug)]
pub struct ChangeCommitmentInner<C: Scheme>(C::Commitment);

impl<C> Canonicalize for ChangeCommitmentInner<C>
where
    C: Scheme,
    C::Commitment: Canonicalize,
{
    fn canonicalize(&self) -> Vec<u8> {
        let mut data = Vec::<u8>::from("ChangeCommitmentInner");
        data.extend(self.0.canonicalize());
        data
    }
}

type ChangeCommitmentRequest<C> = Envelope<ChangeCommitmentInner<C>, Bundle<C>>;

impl<C, V1, V2> Policy for CocoPolicy<C, V1, V2>
where
    C: Scheme + Clone + 'static,
    C::Commitment: TryFrom<Vec<u8>> + Clone + Canonicalize + 'static,
    V1: ContextVerifier,
    V2: ContextVerifier,
    CertificateInner<V2>: Canonicalize,
    SubjectVerifier<C, V1, V2>: ContextVerifier,
{
    type Signature = <SubjectVerifier<C, V1, V2> as ContextVerifier>::Signature;
    type Update = ChangeCommitmentInner<C>;
    type Context = (C, <SubjectVerifier<C, V1, V2> as ContextVerifier>::Context);
    type Error = <SubjectVerifier<C, V1, V2> as ContextVerifier>::Error;

    fn verify(
        &self,
        msg: &[u8],
        signature: &Self::Signature,
        (params, context): &Self::Context,
    ) -> Result<(), Self::Error> {
        let verifier = coco_verifier::<V1, V2, _>(params.clone(), self.c.clone());
        verifier.verify_bytes(msg, signature, context)
    }

    fn update(
        &mut self,
        update: Envelope<Self::Update, Self::Signature>,
        (params, context): &Self::Context,
    ) -> Result<(), Self::Error> {
        let verifier = coco_verifier::<V1, V2, _>(params.clone(), self.c.clone());
        self.c = verifier.open_into(update, context)?.0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::CertificateAuthority;
    use crate::cocommitments::{CocoCa, CocoSigner};
    use crate::commitments::Scheme as _;
    use crate::signature::tests::key_pairs;
    use crate::signature::ContextSigner;
    use proptest::prelude::*;

    type Scheme = crate::commitments::Pedersen;

    proptest! {
        #[test]
        fn test_cocommitment_policy(
            ca: CocoCa<Scheme>,
            identity: Identity,
            key in key_pairs(),
            msg: Vec<u8>
        ) {
            let (policy, comm) = CocoPolicy::create(ca.params(), &identity);
            let bundle = CocoSigner::try_new(&identity, &key, ca.params(), comm)?.sign_bytes(&msg, &ca);
            let context = &(ca.params().clone(), ((), ca.verifier(), ()));
            policy.verify(&msg, &bundle, context)?;
        }

        #[test]
        fn test_cocommitment_policy_bad_proof(
            ca: CocoCa<Scheme>,
            identity: Identity,
            bad_identity: Identity,
            key in key_pairs(),
            msg: Vec<u8>
        ) {
            let mut rng = rand::thread_rng();
            let params = ca.params();

            let (policy, _) = CocoPolicy::create(ca.params(), &identity);
            let (bad_c, bad_r) = params.commit(&bad_identity.canonicalize(), &mut rng);
            let bundle = CocoSigner::try_new(&bad_identity, &key, ca.params(), (bad_c, bad_r))?.sign_bytes(&msg, &ca);
            let context = &(ca.params().clone(), ((), ca.verifier(), ()));
            prop_assert!(policy.verify(&msg, &bundle, context).is_err());
        }

        #[test]
        fn test_cocommitment_policy_bad_signature(
            ca: CocoCa<Scheme>,
            cleartext: Identity,
            key in key_pairs(),
            bad_key in key_pairs(),
            msg: Vec<u8>
        ) {
            prop_assume!(bad_key.public != key.public);
            let mut rng = rand::thread_rng();
            let params = ca.params();

            let (policy, comm1) = CocoPolicy::create(ca.params(), &cleartext);
            let (cert, comm2) = ca.issue(cleartext.clone(), key.public);
            let proof = params.prove_equality(&cleartext.canonicalize(), &comm1, &comm2, &mut rng);
            let signature = bad_key.sign_bytes(&msg, &());
            let bundle = Bundle::<Scheme>::new_with_extra(cert, signature, proof);
            let context = &(ca.params().clone(), ((), ca.verifier(), ()));
            prop_assert!(policy.verify(&msg, &bundle, &context).is_err());
        }


        #[test]
        fn test_cocommitment_policy_update(
            ca: CocoCa<Scheme>,
            (initial_key, initial_subject) in (key_pairs(), any::<Identity>()),
            updates in prop::collection::vec((key_pairs(), any::<Identity>()), 1..10),
            msg: Vec<u8>
        ) {
            let mut rng = rand::thread_rng();
            let params = ca.params();
            let context = &(ca.params().clone(), ((), ca.verifier(), ()));

            let (mut policy, (mut old_c, mut old_r)) = CocoPolicy::create(ca.params(), &initial_subject);

            let mut old_subject = initial_subject;
            let mut old_key = initial_key;
            for (new_key, new_subject) in updates {
                let old_signer = CocoSigner::try_new(&old_subject, &old_key, ca.params(), (old_c, old_r))?;
                let old_bundle = old_signer.sign_bytes(&msg, &ca);

                policy.verify(&msg, &old_bundle, &context)?;

                let (new_c, new_r) = params.commit(&new_subject.canonicalize(), &mut rng);

                let update_inner = ChangeCommitmentInner(new_c);
                let update = old_signer.wrap(update_inner, &ca);

                let new_signer = CocoSigner::try_new(&new_subject, &new_key, params, (new_c, new_r))?;
                let new_bundle = new_signer.sign_bytes(&msg, &ca);

                if new_subject != old_subject {
                    let bad_update_inner = ChangeCommitmentInner(new_c);
                    let bad_update = new_signer.wrap(bad_update_inner, &ca);
                    prop_assert!(policy.update(bad_update, &context).is_err());
                }

                policy.update(update, &context)?;
                policy.verify(&msg, &new_bundle, &context)?;

                old_subject = new_subject;
                old_key = new_key;
                old_c = new_c;
                old_r = new_r;
            }
        }
    }
}
