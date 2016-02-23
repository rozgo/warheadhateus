use error::ParseRegionError;
use std::fmt;
use std::str::FromStr;

/// AWS Region
#[derive(Debug,PartialEq)]
pub enum Region {
    /// us-east-1
    UsEast1,
    ///
    UsWest1,
    ///
    UsWest2,
    ///
    EuWest1,
    ///
    EuCentral1,
    ///
    ApSoutheast1,
    ///
    ApNortheast1,
    ///
    ApSoutheast2,
    ///
    SaEast1,
}

impl Default for Region {
    fn default() -> Region {
        Region::UsEast1
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let display: String = self.into();
        write!(f, "{}", display)
    }
}

impl FromStr for Region {
    type Err = ParseRegionError;

    fn from_str(s: &str) -> Result<Region, ParseRegionError> {
        match s {
            "us-east-1" => Ok(Region::UsEast1),
            "us-west-1" => Ok(Region::UsWest1),
            "us-west-2" => Ok(Region::UsWest2),
            "eu-west-1" => Ok(Region::EuWest1),
            "eu-central-1" => Ok(Region::EuCentral1),
            "ap-southeast-1" => Ok(Region::ApSoutheast1),
            "ap-northeast-1" => Ok(Region::ApNortheast1),
            "ap-southeast-2" => Ok(Region::ApSoutheast2),
            "sa-east-1" => Ok(Region::SaEast1),
            _ => Err(ParseRegionError),
        }
    }
}

/// Translates region enum into AWS format.  EG: us-east-1
impl<'a> Into<String> for &'a Region {
    fn into(self) -> String {
        match *self {
            Region::UsEast1 => "us-east-1".to_owned(),
            Region::UsWest1 => "us-west-1".to_owned(),
            Region::UsWest2 => "us-west-2".to_owned(),
            Region::EuWest1 => "eu-west-1".to_owned(),
            Region::EuCentral1 => "eu-central-1".to_owned(),
            Region::ApSoutheast1 => "ap-southeast-1".to_owned(),
            Region::ApNortheast1 => "ap-northeast-1".to_owned(),
            Region::ApSoutheast2 => "ap-southeast-2".to_owned(),
            Region::SaEast1 => "sa-east-1".to_owned(),
        }
    }
}
