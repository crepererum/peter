use std::fs::File;
use std::io::{self, Read, Write};

use base64::{decode, encode};
use failure::{err_msg, Error, ResultExt};

const WORLD_PRIVATE: &'static str = "4vQ4EoIcdkSn3liU4Fki9vyx1CsFb5RluE5gZnGfEyg=";
const WORLD_PUBLIC: &'static str = "x+ssYnIlVuk9NkkxFbdXmNXCaAD0YB31aaUz5xsgPVI=";

#[derive(Debug)]
pub enum KeyType {
    Public,
    Private,
}

pub fn is_stdinout(fname: &str) -> bool {
    fname == "-"
}

pub fn is_none(fname: &str) -> bool {
    fname == "."
}

pub fn is_world(fname: &str) -> bool {
    fname == "+"
}

pub fn write_key(fname: &String, data: Box<[u8]>, key_type: &KeyType) -> Result<(), Error> {
    if is_none(&fname) {
        return Ok(());
    }
    if is_world(&fname) {
        return Err(err_msg("Cannot write WORLD key."));
    }

    // encode key data
    let encoded = encode(&data);

    // check if key data belongs to WORLD
    let s: String = match key_type {
        KeyType::Public => if encoded == WORLD_PUBLIC {
            "+".into()
        } else {
            encoded
        },
        KeyType::Private => if encoded == WORLD_PRIVATE {
            "+".into()
        } else {
            encoded
        },
    };

    // write data to actual output (stdout, file)
    if is_stdinout(fname) {
        println!("{}", s);
    } else {
        let mut file = File::create(fname).context(format!("Cannot create key file: {}", fname))?;
        file.write_all(s.as_bytes())
            .context(format!("Cannot write data to key file: {}", fname))?;
    }

    Ok(())
}

pub fn read_key(fname: &String, key_type: &KeyType) -> Result<Option<Box<[u8]>>, Error> {
    if is_none(&fname) {
        return Ok(None);
    }

    // read data from actual source (builtin world, stdin, file)
    let mut buffer = String::new();
    if is_world(&fname) {
        match key_type {
            KeyType::Public => {
                buffer = WORLD_PUBLIC.into();
            }
            KeyType::Private => {
                buffer = WORLD_PRIVATE.into();
            }
        }
    } else if is_stdinout(fname) {
        io::stdin()
            .read_to_string(&mut buffer)
            .context("stdin data cannot be parsed to string")?;
    } else {
        let mut file = File::open(fname).context(format!("Could not open key file: {}", fname))?;
        file.read_to_string(&mut buffer)
            .context(format!("Could not read key as string: {}", fname))?;
    }

    // double check if the source contained a WORLD marker
    buffer = match key_type {
        KeyType::Public => if is_world(&buffer.trim()) {
            WORLD_PUBLIC.into()
        } else {
            buffer
        },
        KeyType::Private => if is_world(&buffer.trim()) {
            WORLD_PRIVATE.into()
        } else {
            buffer
        },
    };

    // decode key data
    Ok(Some(
        decode(buffer.trim())
            .context(format!("Invalid base64 data in key file: {}", fname))?
            .into(),
    ))
}

pub fn open_reader(fname: &String) -> Result<Box<Read>, Error> {
    if is_stdinout(fname) {
        Ok(Box::new(io::stdin()))
    } else {
        Ok(Box::new(
            File::open(fname).context(format!("Cannot open input file: {}", fname))?
        ))
    }
}

pub fn open_writer(fname: &String) -> Result<Box<Write>, Error> {
    if is_stdinout(fname) {
        Ok(Box::new(io::stdout()))
    } else {
        Ok(Box::new(
            File::create(fname).context(format!("Cannot open output file: {}", fname))?
        ))
    }
}
