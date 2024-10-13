// This file implements various montgomery multiplication primitives

use crate::config;
use crate::types::{FheUint, PossiblyFheBool, GroupElementFp, GroupElementFq};

// Montgomery reduction: computes (a * 2^(-32) mod p)
fn montgomery_reduction_p (a: u64) -> u32 {
    let low_a = a & ((1u64 << 32) - 1);
    let q = config::P_INV.wrapping_mul(low_a as u32);
    let prod: u64 = q as u64 * config::P as u64;
    if a >= prod {
        ((a - prod) >> 32) as u32
    }
    else {
        let diff: u64 = prod - a;
        config::P - ((diff >> 32) as u32)
    }
}

// Montgomery initialization (computes a * 2^32 mod p) 
fn montgomery_initialization_p (a: u32) -> u32 {
    montgomery_reduction_p(a as u64 * config::P_64)
}

// Montgomery multiplication: Computes (a * b) mod p
fn montgomery_multiplication_p (a: u32, b: u32) -> u32 {
    let a_init = montgomery_initialization_p(a);
    let b_init = montgomery_initialization_p(b);
    let prod = a_init as u64 * b_init as u64;
    montgomery_reduction_p(prod)
}

pub fn multiply_p (a: GroupElementFp, b: GroupElementFp) -> GroupElementFp {
    let mon_mul = montgomery_multiplication_p(a, b);
    montgomery_reduction_p(mon_mul as u64)
}

// Montgomery reduction: computes (a * 2^(-16) mod q)
fn montgomery_reduction_q (a: u32) -> u16 {
    let low_a = a & ((1u32 << 16) - 1);
    let q = config::Q_INV.wrapping_mul(low_a as u16);
    let prod: u32 = q as u32 * config::Q as u32;
    if a >= prod {
        ((a - prod) >> 16) as u16
    }
    else {
        let diff: u32 = prod - a;
        config::Q - ((diff >> 16) as u16)
    }
}

fn montgomery_initialization_q (a: u16) -> u16 {
    montgomery_reduction_q(a as u32 * config::Q_32)
}

fn montgomery_multiplication_q (a: u16, b: u16) -> u16 {
    let a_init = montgomery_initialization_q(a);
    let b_init = montgomery_initialization_q(b);
    let prod = a_init as u32 * b_init as u32;
    montgomery_reduction_q(prod)
}

pub fn multiply_q (a: GroupElementFq, b: GroupElementFq) -> GroupElementFq {
    let mon_mul = montgomery_multiplication_q(a, b);
    montgomery_reduction_q(mon_mul as u32)
}

// mux returns either a mod 2^length or b mod 2^length, depending on c
// it selects a if c is true, and b if c is false
pub fn mux (a: FheUint, b: FheUint, c: PossiblyFheBool, length: usize) -> FheUint {
    let mut bits = Vec::new();
    let a_extended = a.extend(length);
    let b_extended = b.extend(length);
    for i in 0..length {
        let a_bit = a_extended.bit_at(i);
        let b_bit = b_extended.bit_at(i);
        bits.push(a_bit.and(&c).or(&b_bit.and(&c.not())));
    }
    FheUint::from_fhe_bits(bits)
}

pub struct MontgomeryReductionObject {
    pub psize: usize,
    pub p: FheUint,
    p_inv: FheUint,
    p_powtwo: FheUint,
}

impl MontgomeryReductionObject {
    // Constructs a MontgomeryReductionObject
    // psize is the size of the prime in bits
    // p is the prime
    // p_inv is the inverse of p mod 2^psize
    // p_twopow is 2^(2*psize) mod p
    pub fn new (psize: usize, p: u128, p_inv: u128, p_twopow: u128) -> Self {
        MontgomeryReductionObject {
            psize: psize,
            p: FheUint::from_u128(p).extend(psize),
            p_inv: FheUint::from_u128(p_inv).extend(psize),
            p_powtwo: FheUint::from_u128(p_twopow).extend(2*psize)
        }
    }

    // produces (a * 2^(-psize) mod p)
    // input: 2*psize size FheUint
    pub fn montgomery_reduction_fhe (&self, a: FheUint) -> FheUint {
        let low_a = a.section(0, self.psize);
        let q = self.p_inv.multiply(&low_a, self.psize);
        let prod = q.multiply(&self.p, 2*self.psize);
        let ans1 = a.subtract(&prod, 2*self.psize).section(self.psize, 2*self.psize);
        let diff = prod.subtract(&a, 2*self.psize);
        let ans2 = self.p.subtract(&diff.section(self.psize, 2*self.psize), self.psize);
        let gtr = a.geq(&prod, 2*self.psize);
        mux(ans1, ans2, gtr, self.psize)
    }

    // produces (a * 2^(2*psize) mod p)
    pub fn montgomery_initialization_fhe (&self, a: FheUint) -> FheUint {
        self.montgomery_reduction_fhe(a.multiply(&self.p_powtwo, 2*self.psize))
    }

    // produces (a * b mod p)
    pub fn montgomery_multiplication_fhe (&self, a: FheUint, b: FheUint) -> FheUint {
        let a_init = self.montgomery_initialization_fhe(a);
        let b_init = self.montgomery_initialization_fhe(b);
        self.montgomery_reduction_fhe(a_init.multiply(&b_init, 2*self.psize))
    }

    pub fn multiply_fhe (&self, a: FheUint, b: FheUint) -> FheUint {
        let mon_mul = self.montgomery_multiplication_fhe(a, b);
        self.montgomery_reduction_fhe(mon_mul)
    }

    // subtracts p from a if a >= p, for a < 2p
    pub fn mod_once (&self, a: FheUint) -> FheUint {
        let gtr = a.clone().geq(&self.p, self.psize + 1);
        mux(a.clone().subtract(&self.p, self.psize + 1), a.clone(), gtr, self.psize + 1).extend(self.psize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduction_p() {
        let a = rand::random::<u64>() % ((config::P as u64) << 32);
        let a_red = montgomery_reduction_p(a);
        let recomputed_a = (a_red as u64) << 32;
        assert_eq!((a % config::P as u64), recomputed_a % config::P as u64);
    }

    #[test]
    fn test_montgomery_reduction_q() {
        let a: u32 = rand::random::<u32>() % (config::Q as u32) << 16;
        let a_red = montgomery_reduction_q(a);
        let recomputed_a = (a_red as u32) << 16;
        assert_eq!((a % config::Q as u32), recomputed_a % config::Q as u32);
    }

    #[test]
    fn test_multiplication() {
        // generate random integers u, v
        let u = rand::random::<u32>() % config::P;
        let v = rand::random::<u32>() % config::P;
        // compute u * v mod P
        let uv = multiply_p(u, v);
        // compute u * v mod P using the naive method
        let uv_naive = (u as u64 * v as u64) % (config::P as u64);
        assert_eq!(uv as u64, uv_naive);

        let u = rand::random::<u16>() % config::Q;
        let v = rand::random::<u16>() % config::Q;
        let uv = multiply_q(u, v);
        let uv_naive = (u as u32 * v as u32) % (config::Q as u32);
        assert_eq!(uv as u32, uv_naive);
    }

    #[test]
    fn test_montgomery_fhe() {
        let montgomery = MontgomeryReductionObject::new(32, config::P as u128, config::P_INV as u128, config::P_64 as u128);
        for _ in 0..100 {
            let a_arith = rand::random::<u32>() % config::P;
            let b_arith = rand::random::<u32>() % config::P;
            let a = FheUint::from_u32(a_arith);
            let b = FheUint::from_u32(b_arith);
            let prod = montgomery.multiply_fhe(a, b);
            let expected_prod = multiply_p(a_arith, b_arith);
            assert_eq!(prod.as_u128(), expected_prod as u128);
        }
    }

    #[test]
    fn test_mux () {
        for _ in 0..100 {
            let a_arith: u32 = rand::random::<u32>();
            let b_arith: u32 = rand::random::<u32>();
            let c_bool: bool = rand::random::<bool>();
            let a = FheUint::from_u32(a_arith);
            let b = FheUint::from_u32(b_arith);
            let c = PossiblyFheBool::from_plaintext(c_bool);
            assert_eq!(mux(a, b, c, 32).as_u128(), if c_bool {a_arith as u128} else {b_arith as u128});
        }
    }
}
