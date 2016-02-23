/// Amazon S3 Mode of Operation
pub enum Mode {
    /// Use this mode when transferring a payload in one chunk.
    Normal,
    /// Use this mode when transferring a payload in multiple chunks.
    Chunked,
}
