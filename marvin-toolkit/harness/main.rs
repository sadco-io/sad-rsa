//! Timing harness for the Marvin toolkit.
//!
//! This is the upstream `example/rust-crypto` harness with a `--mode` switch added, so that
//! the same measurement loop can drive either PKCS#1 v1.5 or OAEP decryption. The loop is
//! kept as upstream wrote it: the clock stops after the result has been dropped, so the time
//! includes freeing the returned plaintext.

use anyhow::{Context as _, Result};
use clap::{Parser, ValueEnum};
use rsa::{pkcs8::DecodePrivateKey, sha2::Sha256, Oaep, Pkcs1v15Encrypt, RsaPrivateKey};
use std::fs;
use std::hint::black_box;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    /// RSAES-PKCS1-v1_5 (`Pkcs1v15Encrypt`)
    Pkcs1v15,
    /// RSAES-OAEP with SHA-256, MGF1-SHA-256 and an empty label
    Oaep,
}

#[derive(Parser, Debug)]
#[command(about = "Measure timing of RSA decryption using the sad-rsa crate")]
struct Args {
    /// File with the ciphertexts to decrypt
    #[arg(short, long)]
    infile: PathBuf,

    /// File to write the timing data to
    #[arg(short, long)]
    outfile: PathBuf,

    /// The private key to use for decryption
    #[arg(short, long)]
    keyfile: PathBuf,

    /// Size of individual ciphertexts for decryption
    #[arg(short = 'n', long)]
    size: usize,

    /// Padding scheme to decrypt with
    #[arg(short, long, value_enum, default_value_t = Mode::Pkcs1v15)]
    mode: Mode,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let pem = fs::read_to_string(&args.keyfile)
        .with_context(|| format!("unable to read private key from {}", args.keyfile.display()))?;

    let privkey = RsaPrivateKey::from_pkcs8_pem(&pem)?;

    let mut infile = fs::OpenOptions::new()
        .read(true)
        .open(&args.infile)
        .with_context(|| format!("unable to open {} for reading", args.infile.display()))?;

    // Written unbuffered, one line per decryption, as upstream does: buffering would change
    // what runs between two measurements and so make runs harder to compare with older ones.
    let mut outfile = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.outfile)
        .with_context(|| format!("unable to open {} for writing", args.outfile.display()))?;

    writeln!(outfile, "raw times")?;

    let mut accepted: u64 = 0;
    let mut rejected: u64 = 0;

    loop {
        let mut buffer = vec![0; args.size];

        let n = infile.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        assert!(n == buffer.len());

        let now = Instant::now();
        // The returned plaintext is dropped at the end of this statement, inside the timed
        // region, exactly as in the upstream harness.
        let ok = match args.mode {
            Mode::Pkcs1v15 => {
                black_box(privkey.decrypt(Pkcs1v15Encrypt, black_box(&buffer))).is_ok()
            }
            Mode::Oaep => {
                black_box(privkey.decrypt(Oaep::<Sha256>::new(), black_box(&buffer))).is_ok()
            }
        };
        let elapsed = now.elapsed().as_nanos();

        writeln!(outfile, "{}", elapsed)?;
        if ok {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    println!("done: {accepted} decryptions returned a plaintext, {rejected} returned an error");
    Ok(())
}
