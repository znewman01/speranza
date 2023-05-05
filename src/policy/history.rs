use super::Policy;
use crate::signature::Envelope;

pub type UpdateRequest<P> = Envelope<<P as Policy>::Update, <P as Policy>::Signature>;

struct HistoryPolicy<P: Policy> {
    initial: P,
    history: Vec<UpdateRequest<P>>,
    current: Option<P>,
}

impl<P: Policy> HistoryPolicy<P>
where
    P: Clone,
    UpdateRequest<P>: Clone,
{
    fn new(initial: P) -> Self {
        Self {
            initial,
            history: vec![],
            current: None,
        }
    }

    pub fn current(&self) -> &P {
        self.current.as_ref().unwrap_or(&self.initial)
    }

    pub fn update(
        &mut self,
        update: UpdateRequest<P>,
        context: &P::Context,
    ) -> Result<(), P::Error> {
        self.current
            .get_or_insert_with(|| self.initial.clone())
            .update(update.clone(), context)?;
        self.history.push(update);
        Ok(())
    }

    pub fn history(&self) -> (&P, &[UpdateRequest<P>]) {
        (&self.initial, &self.history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BasicPolicy, RotateVerifier};
    use crate::signature::tests::key_pairs;

    use ed25519_dalek::Signer;
    use proptest::prelude::*;

    type Signature = ed25519_dalek::Signature;

    proptest! {
        #[test]
        fn test_history_current(
            initial in key_pairs(),
            updates in prop::collection::vec(key_pairs(), 1..10),
            msg: Vec<u8>
        ) {
            let mut policy = HistoryPolicy::new(BasicPolicy::from(initial.public));


            let num_updates = updates.len();
            let mut current = initial;
            for update in updates {
                let old_signature = current.sign(&msg);
                prop_assert!(policy.current().verify(&msg, &old_signature, &()).is_ok());

                policy.update(RotateVerifier::make(&current, &update), &())?;

                let new_signature = update.sign(&msg);
                prop_assert!(policy.current().verify(&msg, &new_signature, &()).is_ok());
                if current.public != update.public {
                  prop_assert!(policy.current().verify(&msg, &old_signature, &()).is_err());
                }

                current = update;
            }

            let (_initial, history) = policy.history();
            prop_assert_eq!(history.len(), num_updates);
        }
    }
}
