extern crate rand;
extern crate ed25519_dalek;
extern crate sha2;

use rand::rngs::ThreadRng;
use rand::thread_rng;
use ed25519_dalek::Keypair;
use sha2::Sha512;
use std::io::{stdout, Write};

pub fn run() {
    let bytes = genkey().to_bytes();
    stdout().write_all(&bytes).unwrap();
}

fn genkey() -> Keypair {
    let mut csprng: ThreadRng = thread_rng();
    Keypair::generate::<Sha512, _>(&mut csprng)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_does_not_error() {
        genkey();
    }
}
