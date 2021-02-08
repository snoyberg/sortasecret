use clap::{App, Arg};
use keypair::Keypair;
use std::io::{stdout, Write};

fn main() -> Result<(), keypair::Error> {
    let filename = parse_command();
    let keypair = Keypair::generate()?;
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

pub fn parse_command() -> Option<String> {
    parse_command_from(&mut std::env::args_os()).unwrap_or_else(|e| e.exit())
}

fn parse_command_from<I, T>(args: I) -> Result<Option<String>, clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let matches = App::new("Sorta Secret key generator")
        .version("0.1")
        .author("Michael Snoyman <michael@snoyman.com>")
        .about("Generates keypairs for SortaSecret web app")
        .arg(
            Arg::with_name("file")
                .help("Filename to write key to, if omitted writes to stdout")
                .long("file")
                .value_name("file"),
        )
        .get_matches_from_safe(args)?;
    Ok(matches.value_of("file").map(|s| s.to_string()))
}
