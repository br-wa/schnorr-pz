// This file implements schnorr signatures in plaintext
// This is used to check correctness of the phantom zone implementation

use crate::config;
use crate::types;
use crate::montgomery;

// Dummy hash function
fn hash(bitstring: Vec<bool>) -> types::GroupElementFq {
    let mut hash = 0;
    let length = bitstring.len();
    for i in 0..16 {
        for j in 0..(length/(i+1)) {
            hash = hash ^ ((bitstring[i*j] as u16) << i);
        }
    }
    if hash < config::Q {
        hash
    }
    else {
        hash - config::Q
    }
}

fn exp(mut base: types::GroupElementFp, mut pow: types::GroupElementFq) -> types::GroupElementFp {
    let mut g_pow = 1;
    while pow > 0 {
        if pow & 1 == 1 {
            g_pow = montgomery::multiply_p(g_pow, base);
        }
        base = montgomery::multiply_p(base, base);
        pow = pow >> 1;
    }
    g_pow
}

pub fn init(sk: types::GroupElementFq) -> types::GroupElementFp {
    exp(config::G, config::Q - sk)
}

fn to_bits (r: types::GroupElementFp) -> Vec<bool> {
    let mut output = Vec::new();
    for i in 0..32 {
        output.push((r >> i) & 1 == 1);
    }
    output
}

fn hash_two (r: types::GroupElementFp, msg: types::Message) -> types::GroupElementFq {
    let mut bitstring = to_bits(r);
    bitstring.extend(msg.get_bitstring());
    hash(bitstring)
}

pub fn sign(sk: types::GroupElementFq, msg: types::Message) -> (types::GroupElementFq, types::GroupElementFq) {
    let k = rand::random::<types::GroupElementFq>();
    let r = exp(config::G, k);
    let e =  hash_two(r, msg);
    let xe = montgomery::multiply_q(e, sk);
    let mut s = (k as u32) + (xe as u32);
    if s >= (config::Q as u32) {
        s -= config::Q as u32;
    }
    (e, s as u16)
}

pub fn verify (pk: types::GroupElementFp, msg: types::Message, (e, s): (types::GroupElementFq, types::GroupElementFq)) -> bool {
    let r1 = exp(config::G, s);
    let r2 = exp(pk, e);
    let r = montgomery::multiply_p(r1, r2);
    let e_out = hash_two(r, msg);
    e_out == e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr() {
        let sk = rand::random::<types::GroupElementFq>() % config::Q;
        let pk = init(sk);
        let msg = types::Message::from_string("1234567890a~!@#ABCDEF.;/qwertyui".to_string());
        let (e, s) = sign(sk, msg);
        assert!(verify(pk, msg, (e, s)));
    }
}