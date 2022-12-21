use blake2b_simd::Params;
use orchard::{
    keys::{SpendAuthorizingKey, SpendingKey},
    note::Nullifier,
    note::RandomSeed,
    Address,
};
use pasta_curves::{
    arithmetic::{CurveExt, FieldExt},
    group::ff::PrimeField,
    group::GroupEncoding,
    pallas::{Point, Scalar},
    Fp,
};
use rand_core::{CryptoRng, RngCore};
pub struct BundleShieldingRng(pub [u8; 32]);

fn sample_uniform(n: u32, rng: &mut impl RngCore) -> u32 {
    loop {
        let wide = rng.next_u32() as u64 * n as u64;
        let high = (wide >> 32) as u32;
        let low = (wide & u32::MAX as u64) as u32; // maybe just wide as u32 ?
        if low <= u32::MAX - n || low <= u32::MAX - (u32::MAX - n) % n {
            return high;
        }
    }
}

fn shuffle<T>(x: &mut [T], rng: &mut impl RngCore) {
    for i in (1..x.len()).rev() {
        let j = sample_uniform((i + 1) as u32, rng);
        x.swap(i, j as usize);
    }
}

impl BundleShieldingRng {
    pub fn shuffle_inputs<T>(&self, inputs: &mut [T]) {
        let mut rng = Blake2bCtrModeRng::new(&self.0, b"Inps_Permutation");
        shuffle(inputs, &mut rng)
    }
    pub fn shuffle_outputs<T>(&self, outputs: &mut [T]) {
        let mut rng = Blake2bCtrModeRng::new(&self.0, b"Outs_Permutation");
        shuffle(outputs, &mut rng);
    }
    pub fn for_action(&self, i: u32) -> ActionShieldingRng {
        let digest = Params::new()
            .personal(b"ActionShieldSeed")
            .hash_length(32)
            .to_state()
            .update(&self.0)
            .update(&i.to_le_bytes())
            .finalize();
        ActionShieldingRng(digest.as_bytes().try_into().unwrap())
    }
}

struct Blake2bCtrModeRng {
    personal: [u8; 16],
    seed: [u8; 32],
    counter: u32,
    buffer: [u8; 64],
    offset: usize,
}

impl Blake2bCtrModeRng {
    fn new(seed: &[u8; 32], personal: &[u8; 16]) -> Self {
        Blake2bCtrModeRng {
            personal: personal.clone(),
            seed: seed.clone(),
            counter: 0,
            buffer: [0u8; 64],
            offset: 64, // to trigger buffer initialization
        }
    }
}

impl RngCore for Blake2bCtrModeRng {
    fn next_u32(&mut self) -> u32 {
        if self.offset >= 64 {
            let digest = Params::new()
                .personal(&self.personal)
                .hash_length(64)
                .to_state()
                .update(&self.seed)
                .update(&self.counter.to_le_bytes())
                .finalize();
            self.buffer[..].copy_from_slice(digest.as_ref());
            self.offset = 0;
            self.counter += 1;
        }
        let array: [u8; 4] = self.buffer[self.offset..self.offset + 4]
            .try_into()
            .unwrap();
        self.offset += 4;
        ((array[0] as u32) << 0)
            + ((array[1] as u32) << 8)
            + ((array[2] as u32) << 16)
            + ((array[3] as u32) << 24)
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unimplemented!()
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unimplemented!()
    }
}

pub struct ActionShieldingRng(pub [u8; 32]);

fn to_scalar(bytes: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_wide(bytes)
}

fn to_base(bytes: &[u8; 64]) -> Fp {
    Fp::from_bytes_wide(bytes)
}

impl ActionShieldingRng {
    fn random<const N: usize>(&self, dst: &[u8]) -> [u8; N] {
        Params::new()
            .personal(b"ActionExpandSeed")
            .hash_length(N)
            .to_state()
            .update(&self.0)
            .update(dst)
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap()
    }

    pub fn alpha(&self) -> Scalar {
        to_scalar(&self.random(b"alpha"))
    }

    pub fn rcv(&self) -> Scalar {
        to_scalar(&self.random(b"rcv"))
    }

    pub fn dummy_recipient(&self) -> Address {
        let mut raw_address = [0u8; 43];
        let d: [u8; 11] = self.random(b"dummy_d");
        let g_d = Point::hash_to_curve("z.cash:Orchard-gd")(&d);
        let ivk = to_scalar(&self.random(b"dummy_ivk"));
        let pk_d = g_d * ivk;
        raw_address[..11].copy_from_slice(&d);
        raw_address[11..].copy_from_slice(&pk_d.to_bytes());
        Address::from_raw_address_bytes(&raw_address).unwrap()
    }

    pub fn dummy_ock(&self) -> [u8; 32] {
        self.random(b"dummy_ock")
    }

    pub fn dummy_op(&self) -> [u8; 64] {
        self.random(b"dummy_op")
    }

    pub fn dummy_rseed_old(&self, rho: &Nullifier) -> RandomSeed {
        RandomSeed::from_bytes(self.random(b"dummy_rseed_old"), rho).unwrap()
    }

    pub fn rseed_new(&self, rho: &Nullifier) -> RandomSeed {
        RandomSeed::from_bytes(self.random(b"rseed_new"), rho).unwrap()
    }

    pub fn dummy_sk(&self) -> SpendingKey {
        SpendingKey::from_bytes(self.random(b"dummy_sk")).unwrap()
    }

    pub fn dummy_rho(&self) -> Nullifier {
        Nullifier::from_bytes(&to_base(&self.random(b"dummy_rho")).to_repr()).unwrap()
    }

    pub fn dummy_ask(&self) -> SpendAuthorizingKey {
        (&self.dummy_sk()).into()
    }

    /*
    pub fn spend_auth_T(&self) -> [u8; 32] {
        &self.random(b"spend_auth_T", 32)
    */
}

pub struct MockEncryptionRng {
    op: [u8; 64],
    ock: [u8; 32],
    state: usize,
}

impl From<&ActionShieldingRng> for MockEncryptionRng {
    fn from(rng: &ActionShieldingRng) -> Self {
        MockEncryptionRng {
            op: rng.dummy_op(),
            ock: rng.dummy_ock(),
            state: 0,
        }
    }
}

impl RngCore for MockEncryptionRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self.state {
            0 => dest.copy_from_slice(&self.ock),
            1 => dest.copy_from_slice(&self.op),
            _ => panic!(),
        }
        self.state += 1;
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unimplemented!()
    }
}

impl CryptoRng for MockEncryptionRng {}
