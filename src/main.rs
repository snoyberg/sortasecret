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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cli::Command::*;
    match cli::parse_command() {
        GenKey(file) => genkey::run(file)?,
        Server(server) => {
            let mut rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(server))?
        },
    }

    Ok(())
}
