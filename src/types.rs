use phantom_zone::FheBool;

// GroupElementFp is a type alias for a u32
// GroupElementFq is a type alias for a u16
pub type GroupElementFp = u32;
pub type GroupElementFq = u16;

pub const MESSAGE_SIZE: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message([bool; MESSAGE_SIZE]);

impl Message {
    pub fn to_string(&self) -> String {
        let mut msg_str = String::new();
        for i in 0..(MESSAGE_SIZE/8) {
            let mut byte = 0;
            for j in 0..8 {
                byte = byte | (self.0[i*8 + j] as u8) << j;
            }
            msg_str.push(byte as char);
        }
        msg_str
    }

    pub fn from_string(msg_str: String) -> Self {
        let bytes = msg_str.as_bytes(); 
        let mut msg = [false; MESSAGE_SIZE];
        for i in 0..(MESSAGE_SIZE/8) {
            let byte = bytes[i];
            for j in 0..8 {
                msg[i*8 + j] = (byte >> j) & 1 == 1;
            }
        }
        Message(msg)
    }

    pub fn get_bitstring(&self) -> Vec<bool> {
        self.0.to_vec()
    }
}

// PossiblyFheBool is a value that can either be an FheBool or a plaintext bool
// Why do we implement things as PossiblyFheBools?
// We get performance optimizations dealing with regular bools, so we use them when possible.
#[derive(Clone)]
pub struct PossiblyFheBool {
    fhe_bool: Option<FheBool>,
    plaintext: bool,
    is_fhe: bool
}

impl PossiblyFheBool {
    pub fn from_fhe_bool(fhe_bool: FheBool) -> Self {
        PossiblyFheBool {
            fhe_bool: Some(fhe_bool),
            plaintext: false,
            is_fhe: true
        }
    }

    pub fn from_plaintext(plaintext: bool) -> Self {
        PossiblyFheBool {
            fhe_bool: None,
            plaintext: plaintext,
            is_fhe: false
        }
    }

    pub fn is_fhe(&self) -> bool {
        self.is_fhe
    }

    pub fn and(&self, other: &Self) -> Self {
        if self.is_fhe && other.is_fhe {
            PossiblyFheBool::from_fhe_bool(self.fhe_bool.as_ref().unwrap() & other.fhe_bool.as_ref().unwrap())
        }
        else if self.is_fhe {
            return other.and(self)
        }
        else if self.plaintext {
            return other.clone()
        } else {
            PossiblyFheBool::from_plaintext(false)
        }
    }

    pub fn or(&self, other: &Self) -> Self {
        if self.is_fhe && other.is_fhe {
            PossiblyFheBool::from_fhe_bool(self.fhe_bool.as_ref().unwrap() | other.fhe_bool.as_ref().unwrap())
        }
        else if self.is_fhe {
            return other.or(self)
        }
        else if self.plaintext {
            PossiblyFheBool::from_plaintext(true)
        } else {
            other.clone()
        }
    }

    pub fn not(&self) -> Self {
        if self.is_fhe {
            PossiblyFheBool::from_fhe_bool(!self.fhe_bool.as_ref().unwrap())
        }
        else {
            PossiblyFheBool::from_plaintext(!self.plaintext)
        }
    }

    pub fn xor(&self, other: &Self) -> Self {
        if self.is_fhe && other.is_fhe {
            PossiblyFheBool::from_fhe_bool(self.fhe_bool.as_ref().unwrap() ^ other.fhe_bool.as_ref().unwrap())
        }
        else if self.is_fhe {
            return other.xor(self)
        }
        else if self.plaintext {
            return other.not()
        } else {
            other.clone()
        }
    }
}

fn to_bits (a: u128, len: usize) -> Vec<bool> {
    let mut output = Vec::new();
    for i in 0..len {
        output.push((a >> i) & 1 == 1);
    }
    output
}

// FheUint is a generic class for an unsigned integer made up of PossiblyFheBools
#[derive(Clone)]
pub struct FheUint {
    fhe_bits: Vec<PossiblyFheBool>,
    length: usize
}

impl FheUint {
    pub fn from_bitstring (bitstring: Vec<bool>) -> Self {
        let mut fhe_bits = Vec::new();
        for bit in &bitstring {
            fhe_bits.push(PossiblyFheBool::from_plaintext(*bit));
        }
        FheUint {
            fhe_bits: fhe_bits,
            length: bitstring.len()
        }
    }

    pub fn from_u16 (a: u16) -> Self {
        FheUint::from_bitstring(to_bits(a as u128, 16))
    }

    pub fn from_u32 (a: u32) -> Self {
        FheUint::from_bitstring(to_bits(a as u128, 32))
    }

    pub fn from_u64 (a: u64) -> Self {
        FheUint::from_bitstring(to_bits(a as u128, 64))
    }

    pub fn from_u128 (a: u128) -> Self {
        FheUint::from_bitstring(to_bits(a, 128))
    }

    pub fn zero (length: usize) -> Self {
        FheUint {
            fhe_bits: vec![PossiblyFheBool::from_plaintext(false); length],
            length: length
        }
    }

    pub fn one (length: usize) -> Self {
        let mut fhe_bits = Vec::new();
        for i in 0..length {
            if i == 0 {
                fhe_bits.push(PossiblyFheBool::from_plaintext(true));
                continue;
            }
            fhe_bits.push(PossiblyFheBool::from_plaintext(false));
        }
        FheUint {
            fhe_bits: fhe_bits,
            length: length
        }
    }

    // extend extends self to length new_length by padding with zeros or cutting off the end
    pub fn extend (&self, new_length: usize) -> Self {
        let mut new_fhe_bits = Vec::new();
        for i in 0..new_length {
            if i < self.length {
                new_fhe_bits.push(self.fhe_bits[i].clone());
            }
            else {
                new_fhe_bits.push(PossiblyFheBool::from_plaintext(false));
            }
        }
        FheUint {
            fhe_bits: new_fhe_bits,
            length: new_length
        }
    }

    // negate returns something with the value -self mod 2^length
    pub fn negate (&self) -> Self {
        let mut fhe_bits = Vec::new();
        for bit in &self.fhe_bits {
            fhe_bits.push(bit.not());
        }
        // notting everything is 2^length - 1 - self, so we need to add one
        let temp = FheUint {
            fhe_bits: fhe_bits,
            length: self.length
        };
        temp.sum(&FheUint::one(self.length), self.length)
    }

    pub fn subtract (&self, other: &Self, max_length: usize) -> Self {
        let extended_other = other.extend(max_length);
        self.sum(&extended_other.negate(), max_length)
    }

    // from_section returns a new FheUint with the bits from start to end of a FheUint
    pub fn section(&self, start: usize, end: usize) -> Self {
        let mut fhe_bits = Vec::new();
        for i in start..end {
            fhe_bits.push(self.fhe_bits[i].clone());
        }
        FheUint {
            fhe_bits: fhe_bits,
            length: end - start
        }
    }

    // bitshift_with_cap shifts self left by shift bits, and caps the length at cap
    fn bitshift_with_cap(&self, shift: usize, cap: usize) -> Self {
        let mut fhe_bits = Vec::new();
        for _ in 0..shift {
            fhe_bits.push(PossiblyFheBool::from_plaintext(false));
        }
        for i in shift..cap {
            if i >= self.length + shift {
                fhe_bits.push(PossiblyFheBool::from_plaintext(false));
                continue;
            }
            fhe_bits.push(self.fhe_bits[i - shift].clone());
        }
        FheUint {
            fhe_bits: fhe_bits,
            length: cap
        }
    }

    // sum adds self and other mod 2^max_length
    pub fn sum(&self, other: &Self, max_length: usize) -> Self {
        let self_extended = self.extend(max_length);
        let other_extended = other.extend(max_length);
        let mut fhe_bits = Vec::new();
        let mut carry = PossiblyFheBool::from_plaintext(false);
        for i in 0..max_length {
            let original_one = self_extended.fhe_bits[i].xor(&other_extended.fhe_bits[i]);
            let original_carry = self_extended.fhe_bits[i].and(&other_extended.fhe_bits[i]);
            fhe_bits.push(carry.xor(&original_one));
            carry = original_carry.or(&carry.and(&original_one));
        }
        FheUint {
            fhe_bits: fhe_bits,
            length: max_length
        }
    }

    // bit_multiply multiplies self by a single bit
    fn bit_multiply (&self, bit: &PossiblyFheBool) -> Self {
        let mut fhe_bits = Vec::new();
        for i in 0..self.length {
            fhe_bits.push(self.fhe_bits[i].and(bit));
        }
        FheUint {
            fhe_bits: fhe_bits,
            length: self.length
        }
    }

    // dummy_multiply multiplies (self mod 2^length) and (other mod 2^length), which produces a FheUint of length 2*length
    fn dummy_multiply (&self, other: &Self, length: usize) -> Self {
        let mut ans = FheUint::zero(length * 2);
        let self_extended = self.extend(length);
        let other_extended = other.extend(length);
        for i in 0..length {
            ans = ans.sum(
                &self_extended.bit_multiply(&other_extended.fhe_bits[i]).bitshift_with_cap(i, length * 2),
                length * 2
            )
        }
        ans
    }

    // karatsuba multiplies (self mod 2^length) and (other mod 2^length), which produces a FheUint of length 2*length
    fn karatsuba(&self, other: &Self, length: usize) -> Self {
        if length == 0 {
            return FheUint::zero(0);
        }
        if length == 1 {
            let mut fhe_bits = Vec::new();
            fhe_bits.push(self.fhe_bits[0].and(&other.fhe_bits[0]));
            fhe_bits.push(PossiblyFheBool::from_plaintext(false));
            FheUint {
                fhe_bits: fhe_bits,
                length: 2
            }
        } else if length < 4 {
            return self.dummy_multiply(other, length);
        } else if length % 2 == 1 {
                let new_self = self.extend(length + 1);
                let new_other = other.extend(length + 1);
                let product = new_self.karatsuba(&new_other, length + 1);
                return product.extend(length * 2)
        } else {
            let m = length / 2;
            let self_lo = self.section(0, m); // 10
            let self_hi = self.section(m, length); // 10
            let other_lo = other.section(0, m); // 11
            let other_hi = other.section(m, length); // 00
            let z0 = self_lo.karatsuba(&other_lo, m); // 1000
            let z2 = self_hi.karatsuba(&other_hi, m); // 0000
            let self_sum = self_lo.sum(&self_hi, m + 1); // 010
            let other_sum = other_lo.sum(&other_hi, m + 1); // 110
            let prod_sum = self_sum.karatsuba(&other_sum, m + 1); // 011000
            let z1 = prod_sum.subtract(&z0, length + 2).subtract(&z2, length + 2); // 
            z0.sum(
                &z1.bitshift_with_cap(m, 2*length), 2*length
            ).sum(
                &z2.bitshift_with_cap(2*m, 2*length), 2*length
            )
        }
    }

    // multiply produces (self * other) mod 2^max_length
    pub fn multiply (&self, other: &Self, max_length: usize) -> Self {
        let self_extended = self.extend(max_length);
        let other_extended = other.extend(max_length);
        self_extended.karatsuba(&other_extended, max_length).extend(max_length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_from_string() {
        let msg_str = "1234567890a~!@#ABCDEF.;/qwertyui";
        let msg = Message::from_string(msg_str.to_string());
        assert_eq!(msg.to_string(), msg_str);
    }

    // function that converts fheuint to u128, only works if all bits are plaintext
    fn fheuint_to_u128 (fhe_uint: &FheUint) -> u128 {
        let mut res: u128 = 0;
        for i in 0..std::cmp::min(fhe_uint.length, 128) {
            assert!(fhe_uint.fhe_bits[i].is_fhe == false);
            res = res | (fhe_uint.fhe_bits[i].plaintext as u128) << i;
        }
        res
    }

    #[test]
    fn test_arithmetic () {
        let a_arith: u32 = rand::random::<u32>();
        let b_arith: u32 = rand::random::<u32>();
        let c_arith = a_arith.wrapping_add(b_arith);
        let a = FheUint::from_u32(a_arith);
        let b = FheUint::from_u32(b_arith);
        assert_eq!(fheuint_to_u128(&a.sum(&b, 32)), c_arith as u128);
        assert_eq!(fheuint_to_u128(&a.sum(&b, 32).extend(92)), c_arith as u128);

        let d_arith = a_arith.wrapping_sub(b_arith);
        assert_eq!(fheuint_to_u128(&a.subtract(&b, 32)), d_arith as u128);

        // This step tests dummy multiplication
        let e = FheUint::from_bitstring(vec![true, false, true]); // 5
        let f: FheUint = FheUint::from_bitstring(vec![true, true, false]); // 3
        assert_eq!(fheuint_to_u128(&e.dummy_multiply(&f, 3)), 15);
        assert_eq!(fheuint_to_u128(&e.multiply(&f, 3)), 7); // 15 mod 2^3
        assert_eq!(fheuint_to_u128(&e.multiply(&f, 4)), 15);

        // This step tests karatsuba multiplication
        for i in 4..32 {
            let e_temp = e.extend(i);
            let f_temp = f.extend(i);
            assert_eq!(e_temp.karatsuba(&f_temp, i).length, 2*i);
            assert_eq!(fheuint_to_u128(&e_temp.karatsuba(&f_temp, i)), 15);
        }

        let g_arith = a_arith.wrapping_mul(b_arith);
        assert_eq!(fheuint_to_u128(&a.multiply(&b, 32)), g_arith as u128);
    }
}