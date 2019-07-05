use super::keypair::Keypair;
use std::io::{stdout, Write};

pub fn run(filename: Option<String>) -> Result<(), super::keypair::Error> {
    let keypair = Keypair::generate();
    match filename {
        None => {
            let bytes = keypair.encode();
            stdout().write_all(bytes.as_bytes())?;
        }
        Some(filename) => {
            keypair.encode_file(filename)?;
        }
    }

    Ok(())
}
