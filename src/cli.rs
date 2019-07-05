extern crate clap;

use clap::{App, AppSettings, SubCommand, Arg};
use std::ffi::OsString;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    GenKey(Option<String>),
}

pub fn parse_command() -> Command {
    parse_command_from(&mut std::env::args_os()).unwrap_or_else(|e| e.exit())
}

fn parse_command_from<I, T>(args: I) -> Result<Command, clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = App::new("Sorta Secret")
        .version("0.1")
        .author("Michael Snoyman <michael@snoyman.com>")
        .about("Hides sorta-secret information on webpages behind a Captcha")
        .setting(AppSettings::SubcommandRequired)
        .subcommand(SubCommand::with_name("genkey")
                    .about("Generate a new private key")
                    .arg(Arg::with_name("file")
                         .help("Filename to write key to, if omitted writes to stdout")
                         .long("file")
                         .value_name("file")
                         )
        )
        .get_matches_from_safe(args)?;
    if let Some(genkey) = matches.subcommand_matches("genkey") {
        Ok(Command::GenKey(genkey.value_of("file").map(|s| s.to_string())))
    } else {
        panic!("This shouldn't happen {:?}", matches);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_genkey() {
        assert_eq!(
            parse_command_from(["exename", "genkey"].iter()).unwrap(),
            Command::GenKey(None)
        );
    }

    #[test]
    fn test_genkey_file() {
        assert_eq!(
            parse_command_from(["exename", "genkey", "--file", "foo"].iter()).unwrap(),
            Command::GenKey(Some("foo".to_string()))
        );
    }

    #[test]
    fn test_help() {
        parse_command_from(["exename", "--help"].iter()).unwrap_err();
    }

    #[test]
    fn test_badcommand() {
        parse_command_from(["exename", "invalid-command-name"].iter()).unwrap_err();
    }

    #[test]
    fn test_empty() {
        parse_command_from(["exename"].iter()).unwrap_err();
    }

    #[quickcheck]
    fn prop_never_panics(args: Vec<String>) {
        let _ignored = parse_command_from(args.iter());
    }
}
