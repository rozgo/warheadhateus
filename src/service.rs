use error::ParseServiceError;
use std::fmt;
use std::str::FromStr;

/// AWS Services
#[derive(Debug,PartialEq)]
pub enum Service {
    ///
    EC2,
    ///
    S3,
    ///
    DynamoDB,
    ///
    APIGateway,
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let display: String = self.into();
        write!(f, "{}", display)
    }
}

impl FromStr for Service {
    type Err = ParseServiceError;

    fn from_str(s: &str) -> Result<Service, ParseServiceError> {
        match s {
            "ec2" => Ok(Service::EC2),
            "s3" => Ok(Service::S3),
            "dynamodb" => Ok(Service::DynamoDB),
            "apigateway" => Ok(Service::APIGateway),
            _ => Err(ParseServiceError),
        }
    }
}

/// Translates region enum into AWS format.  EG: us-east-1
impl<'a> Into<String> for &'a Service {
    fn into(self) -> String {
        match *self {
            Service::EC2 => "ec2".to_owned(),
            Service::S3 => "s3".to_owned(),
            Service::DynamoDB => "dynamodb".to_owned(),
            Service::APIGateway => "apigateway".to_owned(),
        }
    }
}
