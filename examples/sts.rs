extern crate chrono;
extern crate env_logger;
extern crate warheadhateus;

use chrono::UTC;
use std::io::{self, Write};
use warheadhateus::{AWSAuth, AWSAuthError, hashed_data, HttpRequestMethod, Region, Service};

const EX_STDOUT: &'static str = "Unable to write to stdout!";
const ACCESS_KEY_ID: &'static str = "AKIAJLXUEQWQQ2DGABQA";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
const HOST: &'static str = "sts.amazonaws.com";
const SECRET_ACCESS_KEY: &'static str = "94lsPupTRZa9nTbDnoTYg4BO6+BF19jVZYbrepry";

fn run() -> Result<(), AWSAuthError> {
    let date = UTC::now();
    let fmtdate = &date.format(DATE_TIME_FMT).to_string();
    let url = format!("https://sts.amazonaws.com/\
                                ?Version=2011-06-15\
                                &Action=GetSessionToken\
                                &AWSAccessKeyId=AKIAJLXUEQWQQ2DGABQA\
                                &SignatureVersion=4\
                                &SignatureMethod=HmacSHA256\
                                &Timestamp={}", fmtdate);
    let mut auth = try!(AWSAuth::new(&url));
    let payload_hash = try!(hashed_data(None));

    auth.set_request_type(HttpRequestMethod::GET);
    auth.set_payload_hash(&payload_hash);
    auth.set_date(UTC::now());
    auth.set_service(Service::STS);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.add_header("Host", HOST);
    auth.add_header("X-Amz-Date", &fmtdate);

    let ah = try!(auth.auth_header());
    writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "X-Amz-Date: ", fmtdate).expect(EX_STDOUT);
    writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "Authorization: ", ah).expect(EX_STDOUT);
    writeln!(io::stdout(), "URL: {}", url).expect(EX_STDOUT);

    Ok(())
}

fn main() {
    env_logger::init().expect("Failed to initialize logging!");
    run().expect("Failed to chunk request!");
}
