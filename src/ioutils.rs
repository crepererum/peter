use std::fs::File;
use std::io::{self, Read, Write};

use base64::{decode, encode};
use failure::{Error, ResultExt};

pub fn is_stdinout(fname: &String) -> bool {
    fname == "-"
}

pub fn is_none(fname: &String) -> bool {
    fname == "."
}

pub fn write_key(fname: &String, data: Box<[u8]>) -> Result<(), Error> {
    if is_none(&fname) {
        return Ok(());
    }

    let encoded = encode(&data);
    if is_stdinout(fname) {
        println!("{}", encoded);
    } else {
        let mut file = File::create(fname).context(format!("Cannot create key file: {}", fname))?;
        file.write_all(encoded.as_bytes())
            .context(format!("Cannot write data to key file: {}", fname))?;
    }
    Ok(())
}

pub fn read_key(fname: &String) -> Result<Option<Box<[u8]>>, Error> {
    if is_none(&fname) {
        return Ok(None);
    }

    let mut buffer = String::new();
    if is_stdinout(fname) {
        io::stdin()
            .read_to_string(&mut buffer)
            .context("stdin data cannot be parsed to string")?;
    } else {
        let mut file = File::open(fname).context(format!("Could not open key file: {}", fname))?;
        file.read_to_string(&mut buffer)
            .context(format!("Could not read key as string: {}", fname))?;
    }
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
