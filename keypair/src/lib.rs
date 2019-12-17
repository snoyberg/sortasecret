extern crate base16;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

use std::path::Path;
use std::fs::File;
use std::io::Write;

use cryptoxide::chacha20poly1305::ChaCha20Poly1305;

// FIXME no longer a keypair...
#[derive(Debug, PartialEq)]
pub struct Keypair {
    key: [u8; 16],
}

#[derive(Debug)]
pub enum Error {
    InvalidHex(base16::DecodeError),
    InvalidKeyLength(usize),
    InvalidMessage,
    IO(std::io::Error),
}

impl std::error::Error for Error {
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        // FIXME do better
        write!(fmt, "{:?}", self)
    }
}

impl From<base16::DecodeError> for Error {
    fn from(e: base16::DecodeError) -> Error {
        Error::InvalidHex(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IO(e)
    }
}

impl Keypair {
    pub fn generate() -> Keypair {
        let mut key = [0; 16];
        getrandom::getrandom(&mut key).unwrap();
        Keypair { key }
    }

    pub fn encode(&self) -> String {
        base16::encode_lower(&self.key)
    }

    pub fn decode<T: AsRef<[u8]>>(hex: T) -> Result<Keypair, Error> {
        let bytes = base16::decode(&hex)?;
        let mut key: [u8; 16] = [0; 16];
        if bytes.len() == 16 {
            for i in 0..16 {
                key[i] = bytes[i];
            }
            Ok(Keypair { key })
        } else {
            Err(Error::InvalidKeyLength(bytes.len()))
        }
    }

    pub fn encode_file<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        let mut file = File::create(path)?;
        file.write_all(self.encode().as_bytes())?;
        Ok(())
    }

    #[cfg(test)]
    pub fn decode_file<P: AsRef<Path>>(path: P) -> Result<Keypair, Error> {
        use std::io::Read;
        let mut file = File::open(path)?;
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;
        Keypair::decode(&contents)
    }

    pub fn encrypt<T: AsRef<[u8]>>(&self, msg: T) -> String {
        let msg: &[u8] = msg.as_ref();
        let mut nonce: [u8; 8] = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let mut key = ChaCha20Poly1305::new(&self.key, &nonce, &[]);
        let mut tag = [0; 16];
        let mut output: Vec<u8> = Vec::new();
        output.resize(msg.len(), 0);
        key.encrypt(msg, &mut output, &mut tag);
        format!(
            "{}{}{}",
            base16::encode_lower(&nonce),
            base16::encode_lower(&tag),
            base16::encode_lower(&output),
            )
    }

    pub fn decrypt<T: AsRef<[u8]>>(&self, hex: T) -> Result<Vec<u8>, Error> {
        let noncetagcipher = base16::decode(&hex)?;
        let nonce = &noncetagcipher[0..8];
        let tag = &noncetagcipher[8..24];
        let cipher = &noncetagcipher[24..];
        let mut output: Vec<u8> = Vec::new();
        output.resize(cipher.len(), 0);
        let mut key = ChaCha20Poly1305::new(&self.key, nonce, &[]);
        if key.decrypt(&cipher, &mut output, &tag) {
            Ok(output)
        } else {
            Err(Error::InvalidMessage)
        }
    }
}

#[cfg(test)]
mod test {
    extern crate tempfile;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_encode_decode_memory() {
        let keypair = Keypair::generate();
        assert_eq!(keypair, Keypair::decode(&keypair.encode()).unwrap());
    }

    #[test]
    fn test_encode_decode_files() {
        let keypair = Keypair::generate();
        let dir = tempdir().unwrap();
        let file = dir.path().join("keypair");
        keypair.encode_file(&file).unwrap();
        assert_eq!(keypair, Keypair::decode_file(&file).unwrap());
    }

    #[test]
    fn test_fails_invalid_hex() {
        Keypair::decode("this is not hex").unwrap_err();
    }

    #[test]
    fn test_fails_invalid_signature() {
        Keypair::decode("deadbeef1234").unwrap_err();
    }

    #[test]
    fn test_fails_nonexistent_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("does-not-exist");
        Keypair::decode_file(file).unwrap_err();
    }

    #[quickcheck]
    fn prop_encrypt_decrypt(secret: String) {
        let keypair = Keypair::generate();
        assert_eq!(secret.as_bytes()[..], keypair.decrypt(keypair.encrypt(&secret)).unwrap()[..])
    }
}
