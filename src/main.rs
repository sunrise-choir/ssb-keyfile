use ssb_keyfile::Keypair;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "ssb-keyfile", version = "0.1")]
enum Opt {
    #[structopt(about = "Create a new keyfile")]
    New {
        /// Destination path (file, not directory)
        #[structopt(long, short, parse(from_os_str))]
        path: PathBuf,

        /// Secret key, encoded in base64. If not specified, a new key will be generated.
        #[structopt(long, short)]
        secret: Option<String>,
    },
}

fn main() {
    match Opt::from_args() {
        Opt::New { path, secret } => {
            if let Some(secret) = secret {
                let keypair = Keypair::from_base64(&secret).unwrap_or_else(|| {
                    eprintln!("Failed to decode base64 secret string.");
                    std::process::exit(1);
                });
                ssb_keyfile::write_to_path(&keypair, &path).unwrap_or_else(|e| {
                    eprintln!("Failed to write key file at path: {}", e);
                    std::process::exit(1)
                });
            } else {
                ssb_keyfile::generate_at_path(&path).unwrap_or_else(|e| {
                    eprintln!("Failed to write key file at path: {}", e);
                    std::process::exit(1)
                });
            }
        }
    }
}
