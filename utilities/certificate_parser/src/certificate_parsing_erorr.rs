#[derive(Debug)]
pub enum CertificateError {
    // Parsing-related errors
    ParseError(String),
    UnsupportedFormat(String),
    UnsupportedAlgorithm(String),
    
    // Validation and generation errors
    ValidationError(String),
    GenerationError(String),
    
    // I/O and library-related errors
    IoError(String),
    RcgenError(String),
}