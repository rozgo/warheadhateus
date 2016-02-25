use error::ParseServiceError;
use std::fmt;
use std::str::FromStr;

/// AWS Services
#[derive(Debug,PartialEq)]
pub enum Service {
    /// AWS DynamoDB (Managed NoSQL Database)
    DynamoDB,
    /// AWS EC2 (Virtual Servers in the Cloud)
    EC2,
    /// AWS Identity and Account Management
    IAM,
    /// AWS S3 (Scalable Storage in the Cloud)
    S3,
    /// AWS STS (Security Token Service)
    STS,
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
            "dynamodb" => Ok(Service::DynamoDB),
            "ec2" => Ok(Service::EC2),
            "iam" => Ok(Service::IAM),
            "s3" => Ok(Service::S3),
            "sts" => Ok(Service::STS),
            _ => Err(ParseServiceError),
        }
    }
}

/// Translates region enum into AWS format.  EG: us-east-1
impl<'a> Into<String> for &'a Service {
    fn into(self) -> String {
        match *self {
            Service::DynamoDB => "dynamodb".to_owned(),
            Service::EC2 => "ec2".to_owned(),
            Service::IAM => "iam".to_owned(),
            Service::S3 => "s3".to_owned(),
            Service::STS => "sts".to_owned(),
        }
    }
}
