use std::{env, fs, path::PathBuf};

fn required(name: &str) -> String {
    let value = env::var(name).unwrap_or_else(|_| {
        panic!(
            "missing required build secret environment variable {}",
            name
        )
    });
    if value.is_empty() {
        panic!(
            "build secret environment variable {} must not be empty",
            name
        );
    }
    value
}

fn main() {
    let recaptcha_secret = required("SORTASECRET_RECAPTCHA_SECRET");
    let recaptcha_site = required("SORTASECRET_RECAPTCHA_SITE");
    let keypair = required("SORTASECRET_KEYPAIR");

    println!("cargo:rerun-if-env-changed=SORTASECRET_RECAPTCHA_SECRET");
    println!("cargo:rerun-if-env-changed=SORTASECRET_RECAPTCHA_SITE");
    println!("cargo:rerun-if-env-changed=SORTASECRET_KEYPAIR");

    let output =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo")).join("secrets.rs");
    let source = format!(
        "pub const RECAPTCHA_SECRET: &str = {:?};\n\
         pub const RECAPTCHA_SITE: &str = {:?};\n\
         pub const KEYPAIR: &str = {:?};\n",
        recaptcha_secret, recaptcha_site, keypair
    );
    fs::write(output, source).expect("write generated secrets module");
}
