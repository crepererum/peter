use std::io::{Read, Write};

use failure::{err_msg, Error, ResultExt};
use snow::params::NoiseParams;
use snow::{CryptoResolver, DefaultResolver, NoiseBuilder};

use ioutils::{open_reader, open_writer};

lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_X_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

const HEADER_LENGTH: usize = 96;
const MARKER_LENGTH: usize = 1;
const OVERHEAD_PER_MESSAGE: usize = 16;
const MAX_MESSAGE_LENGTH: usize = 65535;
const PAYLOAD_BUFFER_LENGTH: usize = MAX_MESSAGE_LENGTH - OVERHEAD_PER_MESSAGE;
const MAX_PAYLOAD_LENGTH: usize = PAYLOAD_BUFFER_LENGTH - MARKER_LENGTH;

const PROLOGUE: &'static str = "PETER V2";
const MARKER_NORMAL: u8 = 1;
const MARKER_END: u8 = 2;

pub fn gen_key() -> Box<[u8]> {
    let resolver = DefaultResolver::default();
    let mut dh = resolver.resolve_dh(&PARAMS.dh).unwrap();
    let mut rng = resolver.resolve_rng().unwrap();
    dh.generate(&mut *rng);
    dh.privkey().clone().into()
}

pub fn extract_pubkey(privkey: Box<[u8]>) -> Box<[u8]> {
    let resolver = DefaultResolver::default();
    let mut dh = resolver.resolve_dh(&PARAMS.dh).unwrap();
    dh.set(&privkey);
    dh.pubkey().clone().into()
}

pub fn encrypt(
    privkey: &Box<[u8]>,
    pubkey: &Box<[u8]>,
    fin: &String,
    fout: &String,
) -> Result<(), Error> {
    // open files
    let mut fp_in = open_reader(fin)?;
    let mut fp_out = open_writer(fout)?;

    // set up noise protocol
    let builder: NoiseBuilder = NoiseBuilder::new(PARAMS.clone());
    let mut noise = builder
        .local_private_key(&privkey)
        .remote_public_key(&pubkey)
        .prologue(PROLOGUE.as_bytes())
        .build_initiator()
        .context("Unable to set up noise session")?;

    // IO buffers
    let mut buffer_in = vec![0u8; PAYLOAD_BUFFER_LENGTH];
    let mut buffer_out = vec![0u8; MAX_MESSAGE_LENGTH];

    // write intro
    let s_out = noise
        .write_message(&[], &mut buffer_out)
        .context("Cannot create handshake data")?;
    assert!(s_out == HEADER_LENGTH);
    fp_out
        .write(&buffer_out[..s_out])
        .context("Cannot write handshake data to output file.")?;
    let mut noise = noise
        .into_transport_mode()
        .context("Cannot switch session in transport state")?;

    // encrypt payload
    loop {
        let s_payload = fp_in
            .read(&mut buffer_in[MARKER_LENGTH..])
            .context("Cannot read block from input file.")?;
        let marker = if s_payload < MAX_PAYLOAD_LENGTH {
            MARKER_END
        } else {
            MARKER_NORMAL
        };
        buffer_in[0] = marker;

        let s_out = noise
            .write_message(&buffer_in[..(MARKER_LENGTH + s_payload)], &mut buffer_out)
            .context("Cannot encrypt block")?;
        fp_out
            .write(&buffer_out[..s_out])
            .context("Cannot encrypted block to output file.")?;

        if marker == MARKER_END {
            break;
        }
    }

    Ok(())
}

pub fn decrypt(
    privkey: &Box<[u8]>,
    pubkey: &Option<Box<[u8]>>,
    fin: &String,
    fout: &String,
) -> Result<Box<[u8]>, Error> {
    // open files
    let mut fp_in = open_reader(fin)?;
    let mut fp_out = open_writer(fout)?;

    // set up noise protocol
    let builder: NoiseBuilder = NoiseBuilder::new(PARAMS.clone());
    let mut noise = builder
        .local_private_key(&privkey)
        .prologue(PROLOGUE.as_bytes())
        .build_responder()
        .context("Unable to set up noise session")?;

    // IO buffers
    let mut buffer_in = vec![0u8; MAX_MESSAGE_LENGTH];
    let mut buffer_out = vec![0u8; PAYLOAD_BUFFER_LENGTH];

    // read intro
    fp_in
        .read_exact(&mut buffer_in[..HEADER_LENGTH])
        .context("Cannot read handshake data from input file.")?;
    let s_out = noise
        .read_message(&buffer_in[..HEADER_LENGTH], &mut buffer_out)
        .context("Cannot verify handshake data")?;
    assert!(s_out == 0);
    let mut noise = noise
        .into_transport_mode()
        .context("Cannot switch session in transport state")?;

    // decrypt payload
    loop {
        let s_payload_enc = fp_in
            .read(&mut buffer_in)
            .context("Cannot read encrypted block from input file.")?;
        if s_payload_enc == 0 {
            return Err(err_msg(
                "Unexpected end of input data, encrypted data may be cropped",
            ));
        }

        let s_out = noise
            .read_message(&buffer_in[..s_payload_enc], &mut buffer_out)
            .context("Cannot decrypt block")?;
        fp_out
            .write(&buffer_out[MARKER_LENGTH..s_out])
            .context("Cannot write decrypted block to output file.")?;
        match buffer_out[0] {
            MARKER_NORMAL => {}
            MARKER_END => {
                break;
            }
            _ => {
                return Err(err_msg(
                    "Unknown marker type encountered, seems like a bug on the senders side.",
                ));
            }
        }
    }

    // read soem more data and check if the file got extended
    let s_tail = fp_in
        .read(&mut buffer_in)
        .context("Cannot read encrypted block from input file.")?;
    if s_tail != 0 {
        return Err(err_msg(
            "There is data after the encrypted message, that should not happen!",
        ));
    }

    // check public key
    let remote_static = noise
        .get_remote_static()
        .ok_or_else(|| err_msg("Cannot extract senders static key from session state"))?;
    if let Some(pubkey_data) = pubkey {
        if &**pubkey_data != remote_static {
            return Err(err_msg("Cannot verify senders key"));
        }
    }
    Ok(remote_static.into())
}
