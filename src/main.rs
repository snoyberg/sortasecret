#[macro_use] extern crate serde_derive;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

mod cli;
mod genkey;
mod keypair;
mod server;

fn main() -> Result<(), keypair::Error> {
    use cli::Command::*;
    match cli::parse_command() {
        GenKey(file) => genkey::run(file),
        Server(server) => server::run(server),
    }
}
