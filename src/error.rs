use sodium_sys;
use std::error::Error;
use std::fmt;
use std::string::FromUtf8Error;

#[derive(Debug)]
/// Authentication Error Types
pub enum AWSAuthError {
    Nacl(sodium_sys::SSError),
    ParseError(FromUtf8Error),
}

impl Error for AWSAuthError {
    fn description(&self) -> &str {
        match *self {
            AWSAuthError::Nacl(_) => "Sodium SSError",
            AWSAuthError::ParseError(ref e) => e.description(),
        }
    }
}

impl fmt::Display for AWSAuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let display = match *self {
            AWSAuthError::Nacl(_) => "SSError",
            AWSAuthError::ParseError(_) => "ParseError",
        };
        write!(f, "{}", display)
    }
}

impl From<sodium_sys::SSError> for AWSAuthError {
    fn from(e: sodium_sys::SSError) -> AWSAuthError {
        AWSAuthError::Nacl(e)
    }
}

impl From<FromUtf8Error> for AWSAuthError {
    fn from(e: FromUtf8Error) -> AWSAuthError {
        AWSAuthError::ParseError(e)
    }
}

#[derive(Debug,PartialEq)]
pub struct ParseRegionError;

impl Error for ParseRegionError {
    fn description(&self) -> &str {
        "Unable to parse the given region"
    }
}

impl fmt::Display for ParseRegionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ParseRegionError")
    }
}

#[derive(Debug,PartialEq)]
pub struct ParseServiceError;

impl Error for ParseServiceError {
    fn description(&self) -> &str {
        "Unable to parse the given region"
    }
}

impl fmt::Display for ParseServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ParseServiceError")
    }
}
