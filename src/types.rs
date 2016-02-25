/// Amazon AWS Signing Version
pub enum SigningVersion {
    /// Version 2 (Only use this is the API doesn't support 4 yet)
    Two,
    /// Version 4
    Four,
}
