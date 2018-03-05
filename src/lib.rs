//! Read or create ssb keyfiles.
//!
//! This library uses libsodium internally. In application code, call
//! [`sodiumoxide::init()`](https://dnaq.github.io/sodiumoxide/sodiumoxide/fn.init.html)
//! before using any functions from this module that generate keyfiles.

#![deny(missing_docs)]

extern crate ssb_common;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use std::path::{PathBuf, Path};
use std::io::{self, Read, Write};
use std::fs::{File, OpenOptions, create_dir_all};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::convert::From;

use ssb_common::directory::ssb_directory;
use ssb_common::keys::{PublicKey, SecretKey, gen_keypair};
use regex::{Regex, RegexBuilder};
use serde::de::Error as DeError;
use serde_json::{from_str, to_string_pretty};
use serde_json::error::Error as JsonError;

/// The name of the ssb keyfile.
pub const KEYFILE_NAME: &'static str = "secret";

/// A convenience function that returns the full path to the ssb secret file.
///
/// This uses `ssb_common::directory::ssb_directory` and returns `None` in the
/// same cases.
pub fn keyfile_path() -> Option<PathBuf> {
    ssb_directory().map(|mut path| {
                            path.push(KEYFILE_NAME);
                            path
                        })
}

#[derive(Deserialize)]
struct KeyfileContent {
    public: PublicKey,
    private: SecretKey,
}

#[derive(Serialize)]
struct KeyfileContentBorrow<'a> {
    curve: String,
    public: &'a PublicKey,
    private: &'a SecretKey,
    id: String, // TODO change this once links are implemented in ssb-common
}

impl<'a> KeyfileContentBorrow<'a> {
    fn new(pk: &'a PublicKey, sk: &'a SecretKey) -> KeyfileContentBorrow<'a> {
        KeyfileContentBorrow {
            curve: if pk.is_ed25519() {
                "ed25519".to_string()
            } else {
                unimplemented!()
            },
            public: pk,
            private: sk,
            id: "TODO".to_string(), // TODO change this once links are implemented in ssb-common
        }
    }
}

/// Parse the public and secret key from the content of a key file as a string.
pub fn keys_from_str(secret: &str) -> Result<(PublicKey, SecretKey), JsonError> {
    lazy_static! {
        static ref RE: Regex = RegexBuilder::new(r"^(?:\s*#.*?\n)*(.*?)(?:\s*#.*\n?)$").dot_matches_new_line(true).build().unwrap();
    }

    match RE.captures(secret) {
        None => Err(JsonError::custom("keyfile did not contain a json object")),
        Some(caps) => {
            match caps.get(1) {
                None => Err(JsonError::custom("keyfile did not contain a json object")),
                Some(json) => {
                    let content = from_str::<KeyfileContent>(json.as_str());
                    content.map(|data| (data.public, data.private))
                }
            }
        }
    }
}

/// Read the key file at the given path and parse the keys from it.
///
/// The `KeyfileError` returned by this is never of the
/// `KeyfileError::UnknownLocation` variant.
pub fn load_keys_from_path(path: &Path) -> Result<(PublicKey, SecretKey), KeyfileError> {
    let mut file = File::open(path)?;
    let mut contents = String::with_capacity(727); // length in bytes of the default key file
    file.read_to_string(&mut contents)?;

    Ok(keys_from_str(&contents)?)
}

/// Read the key file from the default location and parse the keys from it.
///
/// Internally, this uses `keyfile_path()` to determine where to look for the
/// key file.
pub fn load_keys() -> Result<(PublicKey, SecretKey), KeyfileError> {
    match keyfile_path() {
        None => Err(KeyfileError::UnknownLocation),
        Some(path) => load_keys_from_path(&path),
    }
}

/// Create a string containing the content of a new secret file for the given keys.
pub fn new_keyfile_string(pk: &PublicKey, sk: &SecretKey) -> String {
    let mut msg = String::with_capacity(705);

    msg.push_str(PRE_COMMENT);
    msg.push_str(&to_string_pretty(&KeyfileContentBorrow::new(pk, sk)).unwrap());
    msg.push_str(POST_COMMENT);

    msg
}

/// Read the keyfile from the default location and parse the keys from it. If
/// the keyfile does not exist, it is created instead (with randomly generated
/// keys).
pub fn load_or_create_keys() -> Result<(PublicKey, SecretKey), KeyfileError> {
    match load_keys() {
        Ok(keys) => Ok(keys),
        Err(KeyfileError::FileError(_)) => {
            match ssb_directory() {
                Some(mut dir) => {
                    create_dir_all(&dir)?;
                    dir.push(KEYFILE_NAME);
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(dir)?;
                    let (pk, sk) = gen_keypair();
                    file.write_all(new_keyfile_string(&pk, &sk).as_bytes())?;
                    Ok((pk, sk))
                }
                None => Err(KeyfileError::UnknownLocation),
            }
        }
        Err(e) => Err(e),
    }
}

/// The reasons why reading keys from a file can fail.
#[derive(Debug)]
pub enum KeyfileError {
    /// An error occured while accessing the file system.
    FileError(io::Error),
    /// The key file did not contain valid (commented) json.
    JsonError(JsonError),
    /// Could not determine the location of the key file.
    UnknownLocation,
}

impl Display for KeyfileError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match *self {
            KeyfileError::FileError(ref err) => write!(f, "Keyfile error: {}", err),
            KeyfileError::JsonError(ref err) => write!(f, "Keyfile error: {}", err),
            KeyfileError::UnknownLocation => write!(f, "Keyfile error: Unknown location"),
        }
    }
}

impl Error for KeyfileError {
    fn description(&self) -> &str {
        match *self {
            KeyfileError::FileError(ref err) => err.description(),
            KeyfileError::JsonError(ref err) => err.description(),
            KeyfileError::UnknownLocation => "Could not determine the location of the key file",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            KeyfileError::FileError(ref err) => Some(err),
            KeyfileError::JsonError(ref err) => Some(err),
            KeyfileError::UnknownLocation => None,
        }
    }
}

impl From<io::Error> for KeyfileError {
    fn from(err: io::Error) -> KeyfileError {
        KeyfileError::FileError(err)
    }
}

impl From<JsonError> for KeyfileError {
    fn from(err: JsonError) -> KeyfileError {
        KeyfileError::JsonError(err)
    }
}

const PRE_COMMENT: &'static str = "# this is your SECRET name.
# this name gives you magical powers.
# with it you can mark your messages so that your friends can verify
# that they really did come from you.
#
# if any one learns this name, they can use it to destroy your identity
# NEVER show this to anyone!!!

";

const POST_COMMENT: &'static str = "

# WARNING! It's vital that you DO NOT edit OR share your secret name
# instead, share your public name";
// TODO add public key with @

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_it() {
        let (pk, sk) = load_or_create_keys().unwrap();
        println!("{:?}, {:?}", pk, sk);
    }
}
