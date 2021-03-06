#[macro_use]
extern crate bitflags;
extern crate chrono;
extern crate curl;
extern crate env_logger;
extern crate regex;
extern crate warheadhateus;
extern crate xml;

use chrono::UTC;
use curl::http;
use regex::Regex;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use warheadhateus::{AWSAuth, AWSAuthError, hashed_data, HttpRequestMethod, Region, Service};
use xml::reader::{EventReader, XmlEvent};

const EX_STDOUT: &'static str = "Unable to write to stdout!";
const DATE_TIME_FMT: &'static str = "%Y%m%dT%H%M%SZ";
const HOST: &'static str = "ec2.amazonaws.com";
const URL_1: &'static str = "https://ec2.amazonaws.com/?Version=2015-10-01\
                            &Action=DescribeInstances&DryRun=true";

bitflags! {
    flags EventFlags: u32 {
        const W_NONE       = 0b00000000,
        const W_ERR        = 0b00000001,
        const W_CODE       = 0b00000010,
        const W_MESS       = 0b00000100,
        const W_RID        = 0b00001000,
    }
}

impl EventFlags {
    pub fn clear(&mut self) {
        self.bits = 0;
    }
}

#[derive(Default, Debug)]
struct XmlError {
    code: String,
    message: String,
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

#[derive(Default, Debug)]
struct Response {
    errors: Vec<XmlError>,
    request_id: String,
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "Response {}\n", self.request_id));
        for error in &self.errors {
            try!(write!(f, "    {}", error));
        }
        Ok(())
    }
}

fn credentials() -> Result<(String, String), io::Error> {
    let mut ak = String::new();
    let mut sk = String::new();

    if let Some(hd) = env::home_dir() {
        let akre = Regex::new(r"^aws_access_key_id = (.*)").expect("Failed to compile regex!");
        let skre = Regex::new(r"^aws_secret_access_key = (.*)").expect("Failed to compile regex!");
        let creds = try!(File::open(hd.join(".aws").join("credentials")));
        let f = BufReader::new(creds);

        for line in f.lines() {
            if let Ok(l) = line {
                if let Some(caps) = akre.captures(&l) {
                    ak.push_str(caps.at(1).expect("Unable to capture!"));
                }

                if let Some(scaps) = skre.captures(&l) {
                    sk.push_str(scaps.at(1).expect("Unable to capture!"));
                }
            }
        }
    }

    Ok((ak, sk))
}

fn run() -> Result<(), AWSAuthError> {
    match credentials() {
        Ok((ak, sk)) => {
            let mut auth = try!(AWSAuth::new(URL_1));
            let payload_hash = try!(hashed_data(None));
            let date = UTC::now();
            let fmtdate = &date.format(DATE_TIME_FMT).to_string();
            auth.set_request_type(HttpRequestMethod::GET);
            auth.set_payload_hash(&payload_hash);
            auth.set_date(UTC::now());
            auth.set_service(Service::EC2);
            auth.set_access_key_id(&ak);
            auth.set_secret_access_key(&sk);
            auth.set_region(Region::UsEast1);
            auth.add_header("Host", HOST);
            auth.add_header("X-Amz-Date", &fmtdate);

            let ah = try!(auth.auth_header());

            let resp = http::handle()
                .get(URL_1)
                .header("Authorization", &ah)
                .header("X-Amz-Date", fmtdate)
                .exec().expect("Failed to perform EC2 GET!");
            let parser = EventReader::new(resp.get_body());
            let mut response: Response = Default::default();
            let mut curr_err: XmlError = Default::default();
            let mut flags = W_NONE;

            for e in parser {
                match e {
                    Ok(XmlEvent::StartElement { name, .. }) => {
                        flags = match &name.local_name[..] {
                            "Code" => { flags | W_CODE },
                            "Error" => { flags | W_ERR },
                            "Message" => { flags | W_MESS },
                            "RequestID" => { flags | W_RID },
                            _ => flags
                        }
                    }
                    Ok(XmlEvent::Characters(s)) => {
                        if flags == W_ERR | W_CODE {
                            curr_err.code = s;
                        } else if flags == W_ERR | W_MESS {
                            curr_err.message = s;
                        } else if flags == W_RID {
                            response.request_id = s;
                        }
                    }
                    Ok(XmlEvent::EndElement { name }) => {
                        match &name.local_name[..] {
                            "Code" => { flags = flags & !W_CODE; },
                            "Error" => {
                                flags = flags & !W_ERR;
                                response.errors.push(curr_err);
                                curr_err = Default::default();
                             },
                            "Message" => { flags = flags & !W_MESS },
                            _ => {}
                        }
                    }
                    Err(e) => {
                        println!("Error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }

            writeln!(io::stdout(), "{}", response).expect(EX_STDOUT);
        }
        Err(e) => {
            writeln!(io::stderr(), "{}", e.description()).expect(EX_STDOUT);
        }
    }

    Ok(())
}

fn main() {
    env_logger::init().expect("Failed to initialize logging!");
    run().expect("Failed to chunk request!");
}
