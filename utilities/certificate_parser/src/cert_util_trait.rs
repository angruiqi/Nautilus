use crate::certificate_type::PublicKeyType;
use crate::certificate_parsing_erorr::CertificateError;

/// A trait for handling various certificate utilities.
#[allow(dead_code)]
pub trait CertUtilsTrait {
    /// Parses a certificate and returns its raw content.
    fn parse(cert_data: &[u8]) -> Result<Vec<u8>, CertificateError>;

    /// Validates a certificate (e.g., signature, expiration).
    fn validate(cert_data: &[u8]) -> Result<bool, CertificateError>;

    /// Extracts the public key from a certificate.
    /// Dynamically determines the key type based on algorithm identifiers.
    fn extract_public_key(cert_data: &[u8]) -> Result<PublicKeyType, CertificateError>;

    /// Exports the certificate to a specific format.
    fn export(cert_data: &[u8]) -> Result<Vec<u8>, CertificateError>;
}