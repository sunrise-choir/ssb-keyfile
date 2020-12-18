//! Read ssb keyfiles, as created by the js implementation.
//!
//! Re-exports [Keypair] from the [ssb-crypto](https://docs.rs/ssb-crypto) crate.

mod classic;
pub use classic::*;
