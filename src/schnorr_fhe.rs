// This file contains the FHE implementation of schnorr signatures

use crate::config;
use crate::montgomery::{MontgomeryReductionObject, mux};
use crate::types::{FheUint, PossiblyFheBool};

pub trait SchnorrFheWithHash {
    fn new (hash_size: usize) -> Self;
    fn hash (&self, msg: Vec<PossiblyFheBool>) -> FheUint;
}

struct DummyHasher {
    hash_size: usize
}

impl SchnorrFheWithHash for DummyHasher {
    fn new (hash_size: usize) -> Self {
        DummyHasher {
            hash_size: hash_size
        }
    }

    fn hash (&self, msg: Vec<PossiblyFheBool>) -> FheUint {
        let mut hash_bits = Vec::new();
        for i in 0..self.hash_size {
            let mut current_bit = PossiblyFheBool::from_plaintext(false);
            for j in 0..(msg.len()/(i+1)) {
                current_bit = current_bit.xor(&msg[i*j]);
            }
            hash_bits.push(current_bit);
        }
        FheUint::from_fhe_bits(hash_bits)
    }
}

struct FheSchnorr<H: SchnorrFheWithHash> {
    montgomery_p: MontgomeryReductionObject,
    montgomery_q: MontgomeryReductionObject,
    g: FheUint,
    hasher: H
}

impl<H: SchnorrFheWithHash> FheSchnorr<H> {
    pub fn new (hasher: H) -> Self {
        FheSchnorr {
            montgomery_p: MontgomeryReductionObject::new(32, config::P as u128, config::P_INV as u128, config::P_64 as u128),
            montgomery_q: MontgomeryReductionObject::new(16, config::Q as u128, config::Q_INV as u128, config::Q_32 as u128),
            g: FheUint::from_u32(config::G),
            hasher: hasher
        }
    }

    pub fn new_with_montgomery (montgomery_p: MontgomeryReductionObject, montgomery_q: MontgomeryReductionObject, g: FheUint, hasher: H) -> Self {
        FheSchnorr {
            montgomery_p: montgomery_p,
            montgomery_q: montgomery_q,
            g: g,
            hasher: hasher
        }
    }

    fn exp_p (&self, base: FheUint, pow: FheUint) -> FheUint {
        let mut result = FheUint::from_u32(1);
        let mut base_pow = base;
        for i in 0..pow.size() {
            result = self.montgomery_p.multiply_fhe(
                result,
                mux(
                    base_pow.clone(), FheUint::one(self.montgomery_p.psize),
                    pow.bit_at(i).clone(),
                    self.montgomery_p.psize
                )
            );
            base_pow = self.montgomery_p.multiply_fhe(base_pow.clone(), base_pow.clone());
        }
        result
    }

    pub fn get_pub_key (&self, sk: FheUint) -> FheUint {
        self.exp_p(self.g.clone(), self.montgomery_q.p.subtract(&sk, self.montgomery_q.psize))
    }

    fn hash_two (&self, r: FheUint, msg: Vec<PossiblyFheBool>) -> FheUint {
        let mut bitstring = vec![];
        for i in 0..self.montgomery_p.psize {
            bitstring.push(r.bit_at(i).clone());
        }
        bitstring.extend(msg);
        self.montgomery_q.mod_once(self.hasher.hash(bitstring))
    }

    pub fn sign (&self, sk: FheUint, nonce: FheUint, msg: Vec<PossiblyFheBool>) -> (FheUint, FheUint) {
        let r = self.exp_p(self.g.clone(), nonce.clone());
        let e = self.hash_two(r, msg);
        let xe = self.montgomery_q.multiply_fhe(e.clone(), sk);
        let mut s = nonce.sum(&xe, self.montgomery_q.psize + 1);
        s = self.montgomery_q.mod_once(s);
        (e, s)
    }

    fn verify_intermediates (&self, pk: FheUint, msg: Vec<PossiblyFheBool>, (e, s): (FheUint, FheUint)) -> (FheUint, FheUint) {
        let r1 = self.exp_p(self.g.clone(), s.clone());
        let r2 = self.exp_p(pk, e.clone());
        let r = self.montgomery_p.multiply_fhe(r1, r2);
        let e_out = self.hash_two(r.clone(), msg);
        (r, e_out)
    }

    pub fn verify (&self, pk: FheUint, msg: Vec<PossiblyFheBool>, (e, s): (FheUint, FheUint)) -> PossiblyFheBool {
        let (_, e_out) = self.verify_intermediates(pk, msg, (e.clone(), s));
        e_out.eq(&e, self.montgomery_q.psize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types;
    use crate::schnorr;
    use crate::montgomery;

    #[test]
    fn test_dummy_hash () {
        let hasher = DummyHasher::new(16);
        let msg_plaintext = types::Message::from_string("1234567890a~!@#ABCDEF.;/qwertyui".to_string());
        let msg = msg_plaintext.get_bitstring().iter().map(|x| PossiblyFheBool::from_plaintext(*x)).collect::<Vec<PossiblyFheBool>>();
        assert_eq!(hasher.hash(msg).as_u128(), schnorr::hash(msg_plaintext.get_bitstring()) as u128);
    }

    #[test]
    fn test_pubkey () {
        let hasher = DummyHasher::new(16);
        let schnorr = FheSchnorr::new(hasher);
        let sk_plaintext = 0;
        let sk = FheUint::from_u16(sk_plaintext);
        assert_eq!(schnorr.get_pub_key(sk).as_u128(), schnorr::init(sk_plaintext) as u128);
    }

    #[test]
    fn test_hash_two () {
        let hasher = DummyHasher::new(16);
        let schnorr = FheSchnorr::new(hasher);
        let r_plaintext = rand::random::<u32>();
        let r = FheUint::from_u32(r_plaintext);
        let msg_plaintext = types::Message::from_string("1234567890a~!@#ABCDEF.;/qwertyui".to_string());
        let msg = msg_plaintext.get_bitstring().iter().map(|x| PossiblyFheBool::from_plaintext(*x)).collect::<Vec<PossiblyFheBool>>();
        assert_eq!(schnorr.hash_two(r, msg).as_u128(), schnorr::hash_two(r_plaintext, msg_plaintext) as u128);
    }

    #[test]
    fn test_sign () {
        let hasher = DummyHasher::new(16);
        let schnorr = FheSchnorr::new(hasher);
        let sk_plaintext = rand::random::<u16>() % config::Q;
        let sk = FheUint::from_u16(sk_plaintext);
        let msg_plaintext = types::Message::from_string("1234567890a~!@#ABCDEF.;/qwertyui".to_string());
        let msg = msg_plaintext.get_bitstring().iter().map(|x| PossiblyFheBool::from_plaintext(*x)).collect::<Vec<PossiblyFheBool>>();
        let nonce_plaintext = rand::random::<u16>();
        let nonce = FheUint::from_u16(nonce_plaintext);
        let (e, s) = schnorr.sign(sk, nonce, msg.clone());
        let (e_expected, s_expected) = schnorr::sign(sk_plaintext, nonce_plaintext, msg_plaintext);
        assert_eq!(e.as_u128(), e_expected as u128);
        assert_eq!(s.as_u128(), s_expected as u128);
    }

    fn schnorr_intermediates (pk: types::GroupElementFp, msg: types::Message, (e, s): (types::GroupElementFq, types::GroupElementFq)) -> (types::GroupElementFp, types::GroupElementFq) {
        let r1 = schnorr::exp(config::G, s);
        let r2 = schnorr::exp(pk, e);
        let r = montgomery::multiply_p(r1, r2);
        let e_out = schnorr::hash_two(r, msg);
        (r, e_out)
    }

    #[test]
    fn test_verify_intermediates () {
        for _ in 0..10 {
            let hasher = DummyHasher::new(16);
            let schnorr = FheSchnorr::new(hasher);

            let sk_plaintext = rand::random::<u16>() % config::Q;
            let pk_plaintext = schnorr::init(sk_plaintext);
            let msg_plaintext = types::Message::from_string("1234567890a~!@#ABCDEF.;/qwertyui".to_string());

            let (e_plaintext, s_plaintext) = schnorr::sign(sk_plaintext, rand::random::<u16>() % config::Q, msg_plaintext);
            let (r_plaintext, e_out_plaintext) = schnorr_intermediates(pk_plaintext, msg_plaintext, (e_plaintext, s_plaintext));
            let (r, e_out) = schnorr.verify_intermediates(
                FheUint::from_u32(pk_plaintext), 
                msg_plaintext.get_bitstring().iter().map(|x| PossiblyFheBool::from_plaintext(*x)).collect::<Vec<PossiblyFheBool>>(), 
                (FheUint::from_u16(e_plaintext), FheUint::from_u16(s_plaintext))
            );
            assert_eq!(r.as_u128(), r_plaintext as u128);
            assert_eq!(e_out.as_u128(), e_out_plaintext as u128);
            assert_eq!(e_out_plaintext, e_plaintext);
            assert_eq!(e_out.as_u128(), e_plaintext as u128);
            assert!(
                e_out.eq(&FheUint::from_u16(e_plaintext), 16).to_bool()
            )
        }
    }

    #[test]
    fn test_schnorr_fhe() {
        let hasher = DummyHasher::new(16);
        let schnorr = FheSchnorr::new(hasher);

        let sk = FheUint::from_u16(rand::random::<u16>() % config::Q);
        let pk = schnorr.get_pub_key(sk.clone());
        let message_plaintext = types::Message::from_string("1234567890a~!@#ABCDEF.;/qwertyui".to_string());
        let msg = message_plaintext.get_bitstring().iter().map(|x| PossiblyFheBool::from_plaintext(*x)).collect::<Vec<PossiblyFheBool>>();
        let nonce_plaintext = rand::random::<u16>() % config::Q;
        let nonce = FheUint::from_u16(nonce_plaintext);
        let (e, s) = schnorr.sign(sk, nonce, msg.clone());
        assert!(schnorr.verify(pk, msg, (e, s)).to_bool());
    }
}