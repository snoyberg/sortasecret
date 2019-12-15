extern crate base16;
extern crate sodiumoxide;

use sodiumoxide::crypto::box_::{PublicKey, SecretKey, gen_keypair};
use sodiumoxide::crypto::sealedbox::{open, seal};
use std::path::Path;
use std::fs::File;
use std::io::Write;

#[derive(Debug)]
pub struct Keypair {
    /// base16 encoded public key
    pub public_hex: String,
    public: PublicKey,
    secret: SecretKey,
}

#[derive(Debug)]
pub enum Error {
    InvalidHex(base16::DecodeError),
    InvalidKey,
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
        let (public, secret) = gen_keypair();
        let public_hex = base16::encode_lower(&public);
        Keypair { secret, public, public_hex }
    }

    pub fn encode(&self) -> String {
        base16::encode_lower(&self.secret)
    }

    pub fn decode<T: AsRef<[u8]>>(hex: T) -> Result<Keypair, Error> {
        let bytes = base16::decode(&hex)?;
        match SecretKey::from_slice(&bytes) {
            None => Err(Error::InvalidKey),
            Some(secret) => {
                let public = secret.public_key();
                let public_hex = base16::encode_lower(&public);
                Ok(Keypair { secret, public, public_hex })
            }
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
        let vec = seal(msg.as_ref(), &self.public);
        base16::encode_lower(&vec)
    }

    pub fn decrypt<T: AsRef<[u8]>>(&self, hex: T) -> Result<Vec<u8>, Error> {
        let cipher = base16::decode(&hex)?;
        open(&cipher, &self.public, &self.secret)
            .map_err(|()| Error::InvalidMessage)
    }
}

impl PartialEq for Keypair {
    fn eq(&self, rhs: &Self) -> bool {
        self.secret == rhs.secret
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
