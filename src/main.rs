#![deny(missing_debug_implementations)]
#![deny(unused_extern_crates)]

extern crate base64;
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate snow;
#[macro_use]
extern crate quicli;

mod core;
mod ioutils;

use failure::err_msg;
use quicli::prelude::*;

use core::{decrypt, encrypt, extract_pubkey, gen_key};
use ioutils::{is_none, is_stdinout, read_key, write_key};

/// Simple encryption tool
#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(flatten)]
    verbosity: Verbosity,

    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Generate new private key
    #[structopt(name = "gen")]
    Generate {
        /// Where to store the private key to, file or '-' (stdout)
        #[structopt(default_value = "-")]
        output: String,
    },

    /// Extract public key from private key
    #[structopt(name = "pub")]
    PubKey {
        /// Where to read the private key from, file or '-' (stdin)
        #[structopt(default_value = "-")]
        input: String,

        /// Where to store the public key to, file or '-' (stdout)
        #[structopt(default_value = "-")]
        output: String,
    },

    /// Encrypt data
    #[structopt(name = "enc")]
    Encrypt {
        /// Where to read your private key from, file or '-' (stdin)
        privkey: String,

        /// Where to read the recipients public key from, file or '-' (stdin)
        pubkey: String,

        /// Where to read the input data from, file; stdin is NOT supported!
        input: String,

        /// Where to store the encrypted data to, file or '-' (stdout)
        #[structopt(default_value = "-")]
        output: String,
    },

    /// Decrypt data
    #[structopt(name = "dec")]
    Decrypt {
        /// Where to read your private key from, file or '-' (stdin)
        privkey: String,

        /// Where to read the senders public key from, file or '-' (stdin) or '.' (ignore)
        #[structopt(default_value = ".")]
        pubkey: String,

        /// Where to read the encrypted data from, file or '-' (stdin)
        #[structopt(default_value = "-")]
        input: String,

        /// Where to store the unencrypted data to, file or '-' (stdout)
        #[structopt(default_value = "-")]
        output: String,

        /// Where to write the senders public key to, file or '-' (stdout) or '.' (ignore)
        #[structopt(default_value = ".")]
        foundkey: String,
    },
}

main!(|args: Cli, log_level: verbosity| {
    info!("started");

    match args.command {
        Command::Generate { output } => {
            info!("generating key");
            let key = gen_key();

            info!("write to output ({})", output);
            write_key(&output, key)?;
        }
        Command::PubKey { input, output } => {
            info!("read private key ({})", input);
            let privkey = read_key(&input)?;

            info!("extracting public key");
            let pubkey = extract_pubkey(privkey);

            info!("write to output ({})", output);
            write_key(&output, pubkey)?;
        }
        Command::Encrypt {
            input,
            output,
            privkey,
            pubkey,
        } => {
            let n_stdin: u8 = vec![&input, &privkey, &pubkey]
                .iter()
                .map(|s| is_stdinout(s) as u8)
                .sum();
            if n_stdin > 1 {
                return Err(err_msg("You can at most have one file read from stdin!"));
            }

            info!("read private key ({})", privkey);
            let privkey = read_key(&privkey)?;

            info!("read public key ({})", pubkey);
            let pubkey = read_key(&pubkey)?;

            info!("encrypting");
            encrypt(&privkey, &pubkey, &input, &output)?;
        }
        Command::Decrypt {
            input,
            output,
            privkey,
            pubkey,
            foundkey,
        } => {
            let n_stdin: u8 = vec![&input, &privkey, &pubkey]
                .iter()
                .map(|s| is_stdinout(s) as u8)
                .sum();
            if n_stdin > 1 {
                return Err(err_msg("You can at most have one file read from stdin!"));
            }

            let n_stdout: u8 = vec![&output, &foundkey]
                .iter()
                .map(|s| is_stdinout(s) as u8)
                .sum();
            if n_stdout > 1 {
                return Err(err_msg("You can at most have one file written to stdout!"));
            }

            info!("read private key ({})", privkey);
            let privkey = read_key(&privkey)?;

            let pubkey = if is_none(&pubkey) {
                info!("no public key provided");
                None
            } else {
                info!("read public key ({})", pubkey);
                Some(read_key(&pubkey)?)
            };

            info!("decrypting");
            let pubkey2 = decrypt(&privkey, &pubkey, &input, &output)?;
            write_key(&foundkey, pubkey2)?;
        }
    }
    info!("done");
});
