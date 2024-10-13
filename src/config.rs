// This file defines various configurations for the schnorr-pz library.
// Note that hard-coding primes helps with implementation, so we do that here.

pub const P: u32 = 1179379;
pub const P_INV: u32 = 2973256251; // inverse of P mod 2^32
pub const P_64: u64 = 640973; // 2^64 mod P
pub const Q: u16 = 65521;
pub const Q_INV: u16 = 4369;
pub const Q_32: u32 = 225; // 2^32 mod Q
pub const G: u32 = 675623;
