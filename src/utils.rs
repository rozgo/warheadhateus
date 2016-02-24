use error::AWSAuthError;
use rustc_serialize::hex::ToHex;
use sodium_sys::crypto::hash::sha2;
use sodium_sys::crypto::utils;
use sodium_sys::crypto::symmetrickey::hmacsha2;
use sodium_sys::crypto::symmetrickey::hmacsha2::Family::SHA256;

/// Hash the given data (or an empty string) with SHA256.
#[cfg_attr(feature = "clippy", allow(string_lit_as_bytes))]
pub fn hashed_data(data: Option<&[u8]>) -> Result<String, AWSAuthError> {
    ::init();
    let data_to_hash = match data {
        Some(d) => d,
        None => "".as_bytes(),
    };
    let state_size = try!(sha2::state_size_256());
    let mut state = utils::secmem::malloc(state_size);
    try!(sha2::init256(&mut state));
    try!(sha2::update256(&mut state, data_to_hash));
    let hash = try!(sha2::finalize256(&mut state));
    Ok(hash.to_hex())
}

pub fn signed_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, AWSAuthError> {
    ::init();
    let state_size = hmacsha2::statebytes(SHA256);
    let mut state = utils::secmem::malloc(state_size);
    try!(hmacsha2::init(&mut state, key, SHA256));
    try!(hmacsha2::update(&mut state, data, SHA256));
    let mac = try!(hmacsha2::finalize(&mut state, SHA256));
    Ok(mac.into())
}
