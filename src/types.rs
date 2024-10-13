use phantom_zone::FheBool;

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

// Why do we implement things as PossiblyFheBools?
// We get performance optimizations dealing with regular bools, so we use them when possible.
pub struct FheUint16([PossiblyFheBool; 16]);
pub struct FheUint32([PossiblyFheBool; 32]);
pub struct FheUint64([PossiblyFheBool; 64]);


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_from_string() {
        let msg_str = "1234567890a~!@#ABCDEF.;/qwertyui";
        let msg = Message::from_string(msg_str.to_string());
        assert_eq!(msg.to_string(), msg_str);
    }
}