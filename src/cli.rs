extern crate clap;

use clap::{App, AppSettings, SubCommand, Arg};
use std::ffi::OsString;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    GenKey(Option<String>),
    Server(Server),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Server {
    pub bind: String,
    pub keyfile: String,
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
        .subcommand(SubCommand::with_name("server")
                    .about("Launch the web server")
                    .arg(Arg::with_name("bind")
                         .help("Host/port to bind to, e.g. 127.0.0.1:8080")
                         .long("bind")
                         .value_name("bind")
                         .required(true)
                         )
                    .arg(Arg::with_name("keyfile")
                         .help("Filename to read key from")
                         .long("keyfile")
                         .value_name("keyfile")
                         .required(true)
                         )
                    )
        .get_matches_from_safe(args)?;
    if let Some(genkey) = matches.subcommand_matches("genkey") {
        Ok(Command::GenKey(genkey.value_of("file").map(|s| s.to_string())))
    } else if let Some(server) = matches.subcommand_matches("server") {
        Ok(Command::Server(Server {
            bind: server.value_of("bind").unwrap().to_string(),
            keyfile: server.value_of("keyfile").unwrap().to_string(),
        }))
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

    #[test]
    fn test_server() {
        assert_eq!(
            parse_command_from(["exename", "server", "--bind", "foo", "--keyfile", "keyfile"].iter()).unwrap(),
            Command::Server(Server {
                bind: "foo".to_string(),
                keyfile: "keyfile".to_string(),
            }),
        )
    }

    #[test]
    fn test_server_incomplete() {
        parse_command_from(["exename", "server", "--bind", "foo"].iter()).unwrap_err();
    }
}
