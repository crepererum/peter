use std::fs::File;
use std::io::{self, Read, Write};

use base64::{decode, encode};

pub fn is_stdinout(fname: &String) -> bool {
    fname == "-"
}

pub fn is_none(fname: &String) -> bool {
    fname == "."
}

pub fn write_data(fname: &String, data: Box<[u8]>) {
    if is_none(&fname) {
        return;
    }

    let encoded = encode(&data);
    if is_stdinout(fname) {
        println!("{}", encoded);
    } else {
        let mut file = File::create(fname).unwrap();
        file.write_all(encoded.as_bytes()).unwrap();
    }
}

pub fn read_data(fname: &String) -> Box<[u8]> {
    let mut buffer = String::new();
    if is_stdinout(fname) {
        io::stdin().read_to_string(&mut buffer).unwrap();
    } else {
        let mut file = File::open(fname).unwrap();
        file.read_to_string(&mut buffer).unwrap();
    }
    decode(buffer.trim()).unwrap().into()
}

pub fn open_reader(fname: &String) -> Box<Read> {
    if is_stdinout(fname) {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(fname).unwrap())
    }
}

pub fn open_writer(fname: &String) -> Box<Write> {
    if is_stdinout(fname) {
        Box::new(io::stdout())
    } else {
        Box::new(File::create(fname).unwrap())
    }
}
