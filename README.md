# SSB-Keyfile

Keyfile operations for ssb: Read keys from a keyfile and create new keyfiles.

Creates and reads keyfiles that are compatible with the js ssb implementation.

```rust
let keypair = ssb_keyfile::generate_at_path("/path/to/secret")?;

let keypair = ssb_keyfile::read_from_path("/path/to/secret")?;
```

```
cargo install ssb-keyfile
ssb-keyfile new --path ~/.ssb-foo/secret
ssb-keyfile new --path ~/.ssb-bar/secret --secret XQfgelZViM6npy...
```
