#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

mod cli;
mod genkey;
mod keypair;

#[derive(Debug)]
enum Error {
    GenKey(keypair::Error)
}

fn main() -> Result<(), Error> {
    use cli::Command::*;
    match cli::parse_command() {
        GenKey(file) => {
            genkey::run(file).map_err(|e| Error::GenKey(e))
        }
    }
}
