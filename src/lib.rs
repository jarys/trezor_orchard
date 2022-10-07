use nonempty::NonEmpty;
use orchard::{
    self,
    builder::{InProgress, SigningMetadata, SigningParts, SpendInfo, Unauthorized, Unproven},
    bundle::{Bundle, Flags},
    circuit::Circuit,
    keys::{FullViewingKey, Scope, SpendValidatingKey},
    note::{Note, TransmittedNoteCiphertext},
    note_encryption::{OrchardDomain, OrchardNoteEncryption},
    tree::{Anchor, MerklePath},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum},
    Action, Address,
};
use pasta_curves::group::ff::PrimeField;
use rand::thread_rng;
use zcash_address::{
    unified::{Address as UnifiedAddress, Container, Encoding, Receiver},
    Network,
};
use zcash_note_encryption::Domain;
use zcash_primitives::memo::Memo;

mod random;
use random::{ActionShieldingRng, BundleShieldingRng, MockEncryptionRng};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct OrchardInput {
    pub note: Note,
    pub merkle_path: MerklePath,
}

impl OrchardInput {
    pub fn dummy(rng: &ActionShieldingRng) -> Self {
        let sk = rng.dummy_sk();
        let fvk: FullViewingKey = (&sk).into();
        let recipient = fvk.address_at(0u64, Scope::External);
        let rho = rng.dummy_rho();
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(0u64),
            rho,
            rng.dummy_rseed_old(&rho),
        );
        let merkle_path = MerklePath::dummy(&mut thread_rng());
        OrchardInput { note, merkle_path }
    }
}

#[derive(Clone, Debug)]
pub enum Recipient {
    External(String),
    Change,
    Dummy,
}

#[derive(Clone, Debug)]
pub struct OrchardOutput {
    pub recipient: Recipient,
    pub amount: u64,
    pub memo: Option<String>,
}

impl OrchardOutput {
    fn dummy() -> Self {
        OrchardOutput {
            recipient: Recipient::Dummy,
            amount: 0,
            memo: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrezorBuilder {
    pub inputs: Vec<Option<OrchardInput>>,
    pub outputs: Vec<Option<OrchardOutput>>,
    pub anchor: Anchor,
    pub fvk: FullViewingKey,
    pub shielding_seed: [u8; 32],
}

impl TrezorBuilder {
    pub fn build<V: TryFrom<i64>>(
        mut self,
    ) -> Result<Bundle<InProgress<Unproven, Unauthorized>, V>, String> {
        let bundle_rng = BundleShieldingRng(self.shielding_seed);
        assert!(
            self.inputs.len() + self.outputs.len() > 0,
            "bundle is empty"
        );
        let actions_count: usize = [self.inputs.len(), self.outputs.len(), 2]
            .into_iter()
            .max()
            .unwrap();
        pad(&mut self.inputs, actions_count);
        pad(&mut self.outputs, actions_count);
        bundle_rng.shuffle_inputs(&mut self.inputs);
        bundle_rng.shuffle_outputs(&mut self.outputs);
        let mut circuits: Vec<Circuit> = vec![];
        let mut actions: Vec<Action<_>> = vec![];
        let mut balance = ValueSum::zero();
        let mut rcv_sum = ValueCommitTrapdoor::from_bytes([0u8; 32]).unwrap();
        for (i, (maybe_input, maybe_output)) in self
            .inputs
            .into_iter()
            .zip(self.outputs.into_iter())
            .enumerate()
        {
            let rng = bundle_rng.for_action(i as u32);
            let (input, fvk, dummy_ask) = match maybe_input {
                Some(input) => (input, self.fvk.clone(), None),
                None => (
                    OrchardInput::dummy(&rng),
                    (&rng.dummy_sk()).into(),
                    Some(rng.dummy_ask()),
                ),
            };

            let output = maybe_output.unwrap_or_else(|| OrchardOutput::dummy());

            let (recipient, scope, ovk) = match output.recipient {
                Recipient::External(addr) => (
                    parse_u_address(addr)?,
                    Scope::External,
                    Some(self.fvk.to_ovk(Scope::External)),
                ),
                Recipient::Change => (
                    (&self.fvk).address_at(0u64, Scope::Internal),
                    Scope::Internal,
                    Some(self.fvk.to_ovk(Scope::Internal)),
                ),
                Recipient::Dummy => (rng.dummy_recipient(), Scope::External, None),
            };

            let memo: Memo = match output.memo {
                None => Memo::Empty,
                Some(x) => x.parse().map_err(|_| "cannot encode memo".to_owned())?,
            };
            let memo = memo.encode().as_array().clone();

            let rcv = ValueCommitTrapdoor::from_bytes(rng.rcv().to_repr()).unwrap();
            let v_net = input.note.value() - NoteValue::from_raw(output.amount);
            let cv_net = ValueCommitment::derive(v_net, rcv.clone());

            let nf_old = input.note.nullifier(&fvk);
            let ak: SpendValidatingKey = fvk.clone().into();
            let alpha = rng.alpha();
            let rk = ak.randomize(&alpha);

            let note = Note::from_parts(
                recipient,
                NoteValue::from_raw(output.amount),
                nf_old,
                rng.rseed_new(&nf_old),
            );

            let cm_new = note.commitment();
            let cmx = cm_new.into();

            let encryptor = OrchardNoteEncryption::new(ovk, note, recipient, memo);
            let epk = encryptor.epk();
            let epk_slice = <OrchardDomain as Domain>::epk_bytes(epk);
            let epk_bytes: [u8; 32] = epk_slice.as_ref().clone().try_into().unwrap();

            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes,
                enc_ciphertext: encryptor.encrypt_note_plaintext(),
                out_ciphertext: encryptor.encrypt_outgoing_plaintext(
                    &cv_net,
                    &cmx,
                    &mut MockEncryptionRng::from(&rng),
                ),
            };

            let auth = SigningMetadata {
                dummy_ask,
                parts: SigningParts {
                    ak: ak.clone(),
                    alpha,
                },
            };
            let action = Action::from_parts(nf_old, rk, cmx, encrypted_note, cv_net, auth);
            let spend = SpendInfo::new(fvk.clone(), input.note, input.merkle_path).unwrap();
            let circuit = Circuit::from_action_context(spend, note, alpha, rcv.clone()).unwrap();

            // update mutables
            balance = (balance + v_net).expect("balance overflow");
            rcv_sum = rcv_sum + &rcv;
            circuits.push(circuit);
            actions.push(action);
        }
        let balance: V = i64::try_from(balance)
            .expect("overflow")
            .try_into()
            .map_err(|_| "cannot convert bundle balance")?;
        Ok(Bundle::from_parts(
            NonEmpty::from_vec(actions).unwrap(),
            Flags::from_parts(true, true),
            balance,
            self.anchor,
            InProgress {
                proof: Unproven { circuits },
                sigs: Unauthorized {
                    bsk: rcv_sum.into_bsk(),
                },
            },
        ))
    }
}

fn pad<T>(xs: &mut Vec<Option<T>>, target_length: usize) {
    for _ in 0..(target_length - xs.len()) {
        xs.push(None);
    }
}

fn parse_u_address(address: String) -> Result<Address, String> {
    let (_, u_address): (Network, UnifiedAddress) =
        Encoding::decode(&address[..]).map_err(|_| "cannot parse recipient address".to_owned())?;

    let recipient = u_address
        .items()
        .into_iter()
        .find_map(|x| match x {
            Receiver::Orchard(addr) => Some(addr),
            _ => None,
        })
        .ok_or("no orchard receiver in ua".to_owned())?;

    let addr = Address::from_raw_address_bytes(&recipient).unwrap();
    Ok(addr)
}
