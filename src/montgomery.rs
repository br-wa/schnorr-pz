// This file implements various montgomery multiplication primitives

use crate::config;
use crate::types;

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

pub fn multiply_p (a: types::GroupElementFp, b: types::GroupElementFp) -> types::GroupElementFp {
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

pub fn multiply_q (a: types::GroupElementFq, b: types::GroupElementFq) -> types::GroupElementFq {
    let mon_mul = montgomery_multiplication_q(a, b);
    montgomery_reduction_q(mon_mul as u32)
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
}
