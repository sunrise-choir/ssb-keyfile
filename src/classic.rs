use serde::{Deserialize, Serialize};
use serde_json::error::Error as JsonError;
pub use ssb_crypto::{AsBytes, Keypair};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use thiserror::Error;

/// Read the key file at the given path and parse the keys from it.
pub fn load_keys_from_path<P: AsRef<Path>>(path: P) -> Result<Keypair, KeyFileError> {
    let mut f = File::open(&path)?;

    // A standard js ssb secret file is 727 bytes
    let mut buf = [0u8; 1024];
    f.read(&mut buf)?;
    let sec_str = std::str::from_utf8(&buf)?;
    keys_from_str(sec_str)
}

// The libsodium "secret" key also contains the public key,
// so there's no need to read the other fields.
#[derive(Debug, Deserialize)]
struct SecretFile {
    private: String,
}

#[derive(Debug, Serialize)]
struct SecretFileFull {
    curve: &'static str,
    public: String,
    private: String,
    id: String,
}

/// Load keys from the string contents of a js ssb secret file.
pub fn keys_from_str(s: &str) -> Result<Keypair, KeyFileError> {
    let raw_sec_str = s
        .lines()
        .filter(|s| !s.starts_with('#'))
        .collect::<Vec<&str>>()
        .concat();
    let sec_str = raw_sec_str.trim_matches(char::from(0));
    let sec = serde_json::from_str::<SecretFile>(&sec_str)?;
    if let Some(kp) = Keypair::from_base64(&sec.private) {
        Ok(kp)
    } else {
        Err(KeyFileError::Decode)
    }
}

fn encode_key(bytes: &[u8]) -> String {
    let mut out = base64::encode_config(bytes, base64::STANDARD);
    out.push_str(".ed25519");
    out
}

/// Create a string containing the content of a new secret file for the given keys,
/// in js ssb commented-json format.
pub fn new_keyfile_string(keypair: &Keypair) -> String {
    let mut msg = Vec::with_capacity(727);

    let mut id = encode_key(&keypair.public.0);
    id.insert(0, '@');

    let kf = SecretFileFull {
        curve: "ed25519",
        public: encode_key(&keypair.public.0),
        private: encode_key(keypair.as_bytes()),
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
#[derive(Error, Debug)]
pub enum KeyFileError {
    #[error("Failed to read from file")]
    FileRead(#[from] io::Error),

    #[error("Secret file isn't valid utf8")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Failed to parse secret file as json")]
    Json(#[from] JsonError),

    #[error("Failed to decode key pair")]
    Decode,
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
    use std::path::PathBuf;

    fn test_data_file(name: &str) -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("test-data");
        d.push(name);
        d
    }

    #[test]
    fn read_js_file() {
        let keypair = load_keys_from_path(test_data_file("secret")).unwrap();

        assert_eq!(
            keypair.public.0,
            [
                31u8, 106, 151, 121, 46, 108, 56, 165, 42, 104, 99, 69, 129, 18, 122, 169, 30, 60,
                250, 80, 30, 63, 64, 189, 150, 175, 72, 86, 84, 12, 162, 215
            ]
        );

        let newkf = new_keyfile_string(&keypair);
        assert_eq!(
            newkf,
            std::fs::read_to_string(test_data_file("secret")).unwrap()
        );
    }

    #[test]
    fn read_go_file() {
        let keypair = load_keys_from_path(test_data_file("secret")).unwrap();
        assert_eq!(
            keypair.public.0,
            [
                31u8, 106, 151, 121, 46, 108, 56, 165, 42, 104, 99, 69, 129, 18, 122, 169, 30, 60,
                250, 80, 30, 63, 64, 189, 150, 175, 72, 86, 84, 12, 162, 215
            ]
        );
    }
}
