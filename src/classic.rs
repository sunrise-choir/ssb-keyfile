use serde::{Deserialize, Serialize};
use serde_json::error::Error as JsonError;
use ssb_crypto::AsBytes;
pub use ssb_crypto::Keypair;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use thiserror::Error;

/// Read and parse the key file from the given [Read] stream.
/// May read more bytes than absolutely necessary.
pub fn read<R: Read>(mut r: R) -> Result<Keypair, KeyFileError> {
    // A standard js ssb secret file is 727 bytes
    let mut buf = [0u8; 1024];
    r.read(&mut buf)?;
    let sec_str = std::str::from_utf8(&buf)?;
    read_from_str(sec_str)
}

/// Read and parse the key file at the given path.
pub fn read_from_path<P: AsRef<Path>>(path: P) -> Result<Keypair, KeyFileError> {
    let f = File::open(&path)?;
    read(f)
}

/// Load keys from the string contents of a js ssb secret file.
pub fn read_from_str(s: &str) -> Result<Keypair, KeyFileError> {
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

/// Create a string containing the content of a new secret file for the given keys,
/// in js ssb commented-json format.
pub fn write(keypair: &Keypair, mut w: impl Write) -> Result<(), io::Error> {
    let mut id = encode_key(&keypair.public.0);
    id.insert(0, '@');

    let kf = SecretFileFull {
        curve: "ed25519",
        public: encode_key(&keypair.public.0),
        private: encode_key(keypair.as_bytes()),
        id: id,
    };

    w.write(PRE_COMMENT.as_bytes())?;
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"");
    let mut ser = serde_json::Serializer::with_formatter(&mut w, formatter);
    kf.serialize(&mut ser).unwrap();

    w.write(POST_COMMENT.as_bytes())?;
    w.write(kf.id.as_bytes())?;
    Ok(())
}

/// Write the given [Keypair] to a new file at the specified path. `path` should include the file name.
/// Fails if the path exists, or if the path is a directory.
pub fn write_to_path<P: AsRef<Path>>(keypair: &Keypair, path: P) -> Result<(), io::Error> {
    if path.as_ref().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "expected a path to a file",
        ));
    }

    if path.as_ref().exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "file exists"));
    }

    if let Some(dir) = path.as_ref().parent() {
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?
        }
    }

    let f = File::create(&path)?;
    write(keypair, f)
}

/// Create a string with the js ssb commented-json format string encoding of the given [Keypair].
pub fn write_to_string(keypair: &Keypair) -> String {
    let mut out = Vec::with_capacity(727);
    write(keypair, io::Cursor::new(&mut out)).unwrap();
    String::from_utf8(out).unwrap()
}

/// Generate a new [Keypair] and write it to the given [Write] stream.
pub fn generate(w: impl Write) -> Result<Keypair, io::Error> {
    let keypair = Keypair::generate();
    write(&keypair, w)?;
    Ok(keypair)
}

/// Generate a new [Keypair] and write it to a new file at the specified [Path].
/// The path should include the file name.
/// Fails if the path exists, or if the path is a directory.
pub fn generate_at_path<P: AsRef<Path>>(path: P) -> Result<Keypair, io::Error> {
    let keypair = Keypair::generate();
    write_to_path(&keypair, path)?;
    Ok(keypair)
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

fn encode_key(bytes: &[u8]) -> String {
    let mut out = base64::encode_config(bytes, base64::STANDARD);
    out.push_str(".ed25519");
    out
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
        let keypair = read_from_path(test_data_file("secret")).unwrap();

        assert_eq!(
            keypair.public.0,
            [
                31u8, 106, 151, 121, 46, 108, 56, 165, 42, 104, 99, 69, 129, 18, 122, 169, 30, 60,
                250, 80, 30, 63, 64, 189, 150, 175, 72, 86, 84, 12, 162, 215
            ]
        );

        let newkf = write_to_string(&keypair);
        assert_eq!(
            newkf,
            std::fs::read_to_string(test_data_file("secret")).unwrap()
        );
    }

    #[test]
    fn read_go_file() {
        let keypair = read_from_path(test_data_file("secret")).unwrap();
        assert_eq!(
            keypair.public.0,
            [
                31u8, 106, 151, 121, 46, 108, 56, 165, 42, 104, 99, 69, 129, 18, 122, 169, 30, 60,
                250, 80, 30, 63, 64, 189, 150, 175, 72, 86, 84, 12, 162, 215
            ]
        );
    }

    #[test]
    fn generate_file() {
        let dir = tempfile::TempDir::new().unwrap();

        // path must not be a dir
        assert!(generate_at_path(dir.path()).is_err());
        let path = dir.path().join("secret");
        let kp = generate_at_path(&path).unwrap();

        // file must not exist
        assert!(generate_at_path(&path).is_err());

        let kp2 = read_from_path(&path).unwrap();
        assert_eq!(kp.public, kp2.public);

        // should create intermediate dirs if they don't exist
        let path = dir.path().join("foo").join("bar");
        let kp = generate_at_path(&path).unwrap();
        let kp2 = read_from_path(&path).unwrap();
        assert_eq!(kp.public, kp2.public);
    }
}
