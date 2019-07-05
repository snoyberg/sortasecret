#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

mod cli;
mod genkey;

fn main() {
    use cli::Command::*;
    match cli::parse_command() {
        GenKey => genkey::run(),
    }
}
