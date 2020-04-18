//! Read ssb keyfiles, as created by the js implementation.
extern crate base64;
extern crate serde;
extern crate serde_json;
extern crate snafu;
#[macro_use]
extern crate serde_derive;
extern crate ssb_crypto;
extern crate ssb_multiformats;

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::error::Error as JsonError;
use snafu::{OptionExt as _, ResultExt as _, Snafu};
pub use ssb_crypto::{PublicKey, SecretKey};
pub use ssb_multiformats::multikey::Multikey;

#[derive(Debug, Deserialize)]
struct SecretFile {
    public: String,
    private: String,
    id: Multikey,
}

/// Read the key file at the given path and parse the keys from it.
pub fn load_keys_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<(PublicKey, SecretKey, Multikey), Error> {
    let mut f = File::open(&path).with_context(|| FileRead {
        path: path.as_ref().to_path_buf(),
    })?;

    // A standard js ssb secret file is 727 bytes
    let mut buf = [0u8; 1024];
    f.read(&mut buf).with_context(|| FileRead {
        path: path.as_ref().to_path_buf(),
    })?;
    let sec_str = std::str::from_utf8(&buf).context(Utf8)?;
    keys_from_str(sec_str)
}

#[derive(Debug, Serialize)]
struct SecretFileFull {
    curve: &'static str,
    public: String,
    private: String,
    id: String,
}

/// Load keys from the string contents of a js ssb secret file.
pub fn keys_from_str(s: &str) -> Result<(PublicKey, SecretKey, Multikey), Error> {
    let raw_sec_str = s
        .lines()
        .filter(|s| !s.starts_with('#'))
        .collect::<Vec<&str>>()
        .concat();
    let sec_str = raw_sec_str.trim_matches(char::from(0));

    // let v = serde_json::from_str::<serde_json::Value>(&sec_str)?;
    let sec = serde_json::from_str::<SecretFile>(&sec_str).context(Json)?;

    let pbytes = decode_b64_key(&sec.public).context(DecodePublic)?;
    let sbytes = decode_b64_key(&sec.private).context(DecodeSecret)?;

    let p = PublicKey::from_slice(&pbytes).context(CreatePublic)?;
    let s = SecretKey::from_slice(&sbytes).context(CreateSecret)?;

    Ok((p, s, sec.id))
}

fn decode_b64_key(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(s.trim_end_matches(".ed25519"), base64::STANDARD)
}

fn encode_key(bytes: &[u8]) -> String {
    let mut out = base64::encode_config(bytes, base64::STANDARD);
    out.push_str(".ed25519");
    out
}

/// Create a string containing the content of a new secret file for the given keys,
/// in js ssb commented-json format.
pub fn new_keyfile_string(pk: &PublicKey, sk: &SecretKey) -> String {
    let mut msg = Vec::with_capacity(727);

    let id = {
        let mut p = encode_key(&pk.0);
        p.insert(0, '@');
        p
    };

    let kf = SecretFileFull {
        curve: "ed25519",
        public: encode_key(&pk.0),
        private: encode_key(&sk.0),
        id: id,
    };

    msg.extend_from_slice(PRE_COMMENT.as_bytes());

    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"");
    let mut ser = serde_json::Serializer::with_formatter(&mut msg, formatter);
    kf.serialize(&mut ser).unwrap();

    msg.extend_from_slice(POST_COMMENT.as_bytes());
    msg.extend_from_slice(kf.id.as_bytes());

    String::from_utf8(msg).unwrap()
}

/// The reasons why reading keys from a file can fail.
#[derive(Debug, Snafu)]
pub enum Error {
    /// An error occured while accessing the file system.
    #[snafu(display("Failed to read secret file at path: {} with error: {}", path.display(), source))]
    FileRead { path: PathBuf, source: io::Error },

    /// Conterting the file contents with std::str::from_utf8() failed.
    #[snafu(display("Secret file isn't valid utf8: {}", source))]
    Utf8 { source: std::str::Utf8Error },

    /// The key file did not contain valid (commented) json.
    #[snafu(display("Failed to deserialize secret file: {}", source))]
    Json { source: JsonError },

    /// The key file did not contain valid (commented) json.
    #[snafu(display("Failed to decode public key: {}", source))]
    DecodePublic { source: base64::DecodeError },

    /// The key file did not contain valid (commented) json.
    #[snafu(display("Failed to decode public key: {}", source))]
    DecodeSecret { source: base64::DecodeError },

    /// The key file did not contain valid (commented) json.
    #[snafu(display("Failed to decode public key."))]
    CreatePublic {},

    /// The key file did not contain valid (commented) json.
    #[snafu(display("Failed to decode public key."))]
    CreateSecret {},
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
# instead, share your public name
# your public name: ";

#[cfg(test)]
mod tests {
    use super::*;

    fn test_data_file(name: &str) -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("test-data");
        d.push(name);
        d
    }

    #[test]
    fn read_js_file() {
        let (pk, sk, _id) = load_keys_from_path(test_data_file("secret")).unwrap();

        assert_eq!(
            pk.0,
            [
                31u8, 106, 151, 121, 46, 108, 56, 165, 42, 104, 99, 69, 129, 18, 122, 169, 30, 60,
                250, 80, 30, 63, 64, 189, 150, 175, 72, 86, 84, 12, 162, 215
            ]
        );
        assert_eq!(pk, sk.public_key());

        let newkf = new_keyfile_string(&pk, &sk);
        assert_eq!(
            newkf,
            std::fs::read_to_string(test_data_file("secret")).unwrap()
        );
    }

    #[test]
    fn read_go_file() {
        let (pk, sk, _id) = load_keys_from_path(test_data_file("secret")).unwrap();
        assert_eq!(
            pk.0,
            [
                31u8, 106, 151, 121, 46, 108, 56, 165, 42, 104, 99, 69, 129, 18, 122, 169, 30, 60,
                250, 80, 30, 63, 64, 189, 150, 175, 72, 86, 84, 12, 162, 215
            ]
        );
        assert_eq!(pk, sk.public_key());
    }
}
