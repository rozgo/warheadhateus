extern crate chrono;
extern crate env_logger;
extern crate warheadhateus;

use chrono::UTC;
use chrono::offset::TimeZone;
use std::io::{self, Write};
use warheadhateus::{AWSAuth, AWSAuthError, hashed_data, HttpRequestMethod, Region, Service};

const EX_STDOUT: &'static str = "Unable to write to stdout!";
const ACCESS_KEY_ID: &'static str = "AKIAIOSFODNN7EXAMPLE";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
const HOST: &'static str = "examplebucket.s3.amazonaws.com";
const SCOPE_DATE: &'static str = "20130524T000000Z";
const SECRET_ACCESS_KEY: &'static str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const URL_1: &'static str = "https://examplebucket.s3.amazonaws.com/test.txt";
const AWS_TEST_1: &'static str = "AWS4-HMAC-SHA256 \
                                  Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_r\
                                  equest,SignedHeaders=host;range;x-amz-content-sha256;\
                                  x-amz-date,\
                                  Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd9\
                                  1039c6036bdb41";

fn run() -> Result<(), AWSAuthError> {
    let mut auth = try!(AWSAuth::new(URL_1));
    let payload_hash = try!(hashed_data(None));
    let scope_date = try!(UTC.datetime_from_str(SCOPE_DATE, DATE_TIME_FMT));
    auth.set_request_type(HttpRequestMethod::GET);
    auth.set_payload_hash(&payload_hash);
    auth.set_date(scope_date);
    auth.set_service(Service::S3);
    auth.set_access_key_id(ACCESS_KEY_ID);
    auth.set_secret_access_key(SECRET_ACCESS_KEY);
    auth.set_region(Region::UsEast1);
    auth.add_header("HOST", HOST);
    auth.add_header("x-amz-content-sha256", &payload_hash);
    auth.add_header("x-amz-date", SCOPE_DATE);
    auth.add_header("Range", "bytes=0-9");

    let ah = try!(auth.auth_header());
    assert!(ah == AWS_TEST_1);
    writeln!(io::stdout(), "\x1b[32;1m{}\x1b[0m{}", "Authorization: ", ah).expect(EX_STDOUT);

    Ok(())
}

fn main() {
    env_logger::init().expect("Failed to initialize logging!");
    run().expect("Failed to chunk request!");
}
