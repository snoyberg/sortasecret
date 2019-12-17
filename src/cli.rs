extern crate clap;

use clap::{App, Arg};
use std::ffi::OsString;

#[derive(Debug, PartialEq, Eq)]
pub struct Server {
    pub bind: String,
    pub keypair: String,
    pub recaptcha_site: String,
    pub recaptcha_secret: String,
}

pub fn parse_command() -> Server {
    parse_command_from(&mut std::env::args_os()).unwrap_or_else(|e| e.exit())
}

fn parse_command_from<I, T>(args: I) -> Result<Server, clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = App::new("Sorta Secret")
        .version("0.1")
        .author("Michael Snoyman <michael@snoyman.com>")
        .about("Hides sorta-secret information on webpages behind a Captcha")
        .arg(Arg::with_name("bind")
             .help("Host/port to bind to, e.g. 127.0.0.1:8080")
             .long("bind")
             .value_name("bind")
             .required(true)
            )
        .arg(Arg::with_name("keypair")
             .help("hex encoded keypair")
             .long("keypair")
             .value_name("keypair")
             .required(true)
            )
        .arg(Arg::with_name("recaptcha-site")
             .help("Recaptcha site key")
             .long("recaptcha-site")
             .value_name("recaptcha-site")
             .required(true)
            )
        .arg(Arg::with_name("recaptcha-secret")
             .help("Recaptcha secret key")
             .long("recaptcha-secret")
             .value_name("recaptcha-secret")
             .required(true)
            )
        .get_matches_from_safe(args)?;
    Ok(Server {
        bind: matches.value_of("bind").unwrap().to_string(),
        keypair: matches.value_of("keypair").unwrap().to_string(),
        recaptcha_site: matches.value_of("recaptcha-site").unwrap().to_string(),
        recaptcha_secret: matches.value_of("recaptcha-secret").unwrap().to_string(),
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_genkey() {
        parse_command_from(["exename", "genkey"].iter()).unwrap_err();
    }

    #[test]
    fn test_genkey_file() {
        parse_command_from(["exename", "genkey", "--file", "foo"].iter()).unwrap_err();
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
            parse_command_from([
                "exename",
                "--bind",
                "foo",
                "--keypair",
                "keypair",
                "--recaptcha-site",
                "sitekey",
                "--recaptcha-secret",
                "secretkey",
                ].iter()).unwrap(),
            Server {
                bind: "foo".to_string(),
                keypair: "keypair".to_string(),
                recaptcha_site: "sitekey".to_string(),
                recaptcha_secret: "secretkey".to_string(),
            },
        )
    }

    #[test]
    fn test_server_incomplete() {
        parse_command_from(["exename", "server", "--bind", "foo"].iter()).unwrap_err();
    }
}
