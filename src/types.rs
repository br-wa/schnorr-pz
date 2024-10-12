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