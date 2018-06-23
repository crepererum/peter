use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::{err_msg, Error, ResultExt};
use snow::params::NoiseParams;
use snow::{CryptoResolver, DefaultResolver, NoiseBuilder};

use ioutils::{is_stdinout, open_reader, open_writer};

lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_X_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

const HEADER_LENGTH: usize = 96;
const OVERHEAD_PER_MESSAGE: usize = 16;
const SIZEMARKER_LENGTH: usize = 8;
const SIZEMARKER_ENC_LENGTH: usize = SIZEMARKER_LENGTH + OVERHEAD_PER_MESSAGE;
const MAX_MESSAGE_LENGTH: usize = 65535;
const MAX_PAYLOAD_PART_LENGTH: usize = MAX_MESSAGE_LENGTH - OVERHEAD_PER_MESSAGE;
const PROLOGUE: &'static str = "PETER V1";

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
    if is_stdinout(&fin) {
        panic!("not implemented")
    }

    // open files
    let mut fp_in = File::open(fin)?;
    let mut fp_out = open_writer(fout)?;

    // detect input length
    let payload_length = fp_in
        .seek(SeekFrom::End(0))
        .context(format!("Cannot seek to end of input file: {}", fin))?;
    fp_in
        .seek(SeekFrom::Start(0))
        .context(format!("Cannot seek to start of input file: {}", fin))?;

    // set up noise protocol
    let builder: NoiseBuilder = NoiseBuilder::new(PARAMS.clone());
    let mut noise = builder
        .local_private_key(&privkey)
        .remote_public_key(&pubkey)
        .prologue(PROLOGUE.as_bytes())
        .build_initiator()
        .context("Unable to set up noise session")?;

    // IO buffers
    let mut buffer_in = vec![0u8; MAX_PAYLOAD_PART_LENGTH];
    let mut buffer_out = vec![0u8; MAX_MESSAGE_LENGTH];

    // write intro
    let s_out = noise
        .write_message(&[], &mut buffer_out)
        .context("Cannot create handshake data")?;
    assert!(s_out == HEADER_LENGTH);
    fp_out.write(&buffer_out[..s_out]).context(format!(
        "Cannot write handshake data to output file: {}",
        fout
    ))?;
    let mut noise = noise
        .into_transport_mode()
        .context("Cannot switch session in transport state")?;
    let mut lenvec: Vec<u8> = vec![];
    lenvec
        .write_u64::<BigEndian>(payload_length)
        .context("Cannot encode payload size")?;
    assert!(lenvec.len() == SIZEMARKER_LENGTH);
    let s_out = noise
        .write_message(&lenvec, &mut buffer_out)
        .context("Cannot encrypt payload size")?;
    assert!(s_out == SIZEMARKER_ENC_LENGTH);
    fp_out.write(&buffer_out[..s_out]).context(format!(
        "Cannot write encrypted payload size to output file: {}",
        fout
    ))?;

    // encrypt payload
    let mut payload_length2 = 0u64;
    loop {
        let s_payload = fp_in
            .read(&mut buffer_in)
            .context(format!("Cannot read block from input file: {}", fin))?;
        if s_payload == 0 {
            break;
        }
        let s_out = noise
            .write_message(&buffer_in[..s_payload], &mut buffer_out)
            .context("Cannot encrypt block")?;
        fp_out
            .write(&buffer_out[..s_out])
            .context(format!("Cannot encrypted block to output file: {}", fout))?;
        payload_length2 += s_payload as u64;
    }
    assert!(payload_length == payload_length2);

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
    let mut buffer_out = vec![0u8; MAX_PAYLOAD_PART_LENGTH];

    // read intro
    fp_in
        .read_exact(&mut buffer_in[..HEADER_LENGTH])
        .context(format!(
            "Cannot read handshake data from input file: {}",
            fin
        ))?;
    let s_out = noise
        .read_message(&buffer_in[..HEADER_LENGTH], &mut buffer_out)
        .context("Cannot verify handshake data")?;
    assert!(s_out == 0);
    let mut noise = noise
        .into_transport_mode()
        .context("Cannot switch session in transport state")?;
    fp_in
        .read_exact(&mut buffer_in[..SIZEMARKER_ENC_LENGTH])
        .context(format!(
            "Cannot read encrypted payload size from input file: {}",
            fin
        ))?;
    let s_out = noise
        .read_message(&buffer_in[..SIZEMARKER_ENC_LENGTH], &mut buffer_out)
        .context("Cannot decrypt payload size")?;
    assert!(s_out == SIZEMARKER_LENGTH);
    let payload_length = (&buffer_out[..SIZEMARKER_LENGTH])
        .read_u64::<BigEndian>()
        .context("Cannot decode payload size")?;

    // decrypt payload
    let mut payload_length2 = 0u64;
    loop {
        let s_payload_enc = fp_in.read(&mut buffer_in).context(format!(
            "Cannot read encrypted block from input file: {}",
            fin
        ))?;
        if s_payload_enc == 0 {
            break;
        }
        let s_out = noise
            .read_message(&buffer_in[..s_payload_enc], &mut buffer_out)
            .context("Cannot decrypt block")?;
        fp_out.write(&buffer_out[..s_out]).context(format!(
            "Cannot write decrypted block to output file: {}",
            fout
        ))?;
        payload_length2 += s_out as u64;
    }
    assert!(payload_length == payload_length2);

    // check public key
    let remote_static = noise.get_remote_static().ok_or::<Error>(err_msg(
        "Cannot extract senders static key from session state",
    ))?;
    if let Some(pubkey_data) = pubkey {
        assert!(&**pubkey_data == remote_static);
    }
    Ok(remote_static.into())
}
