// utilities/certificate_parser/src/certificate_parsing.rs
use crate::certificate_type::{CertificateType, PublicKeyType};
use crate::certificate_parsing_erorr::CertificateError;
use crate::utils::der_utils::DerUtils;
use crate::utils::pem_utils::PemUtils;
use crate::cert_util_trait::CertUtilsTrait;
/// Parses a certificate and extracts its public key.
///
/// Supports PEM, DER, PKCS12, and JKS formats (partial support for the latter two).
pub fn convert_certificate_to_public_key(
    cert_data: &[u8],
    cert_type: CertificateType,
) -> Result<PublicKeyType, CertificateError> {
    let raw_cert = match cert_type {
        CertificateType::PEM => PemUtils::parse(cert_data)?,
        CertificateType::DER => DerUtils::parse(cert_data)?,
    };

    let (_, parsed_cert) = x509_parser::parse_x509_certificate(&raw_cert)
        .map_err(|_| CertificateError::ParseError("Failed to parse certificate".to_string()))?;

    // Extract OID and public key
    let public_key_info = parsed_cert.tbs_certificate.subject_pki;
    let algorithm_oid = public_key_info.algorithm.algorithm.to_string();
    let public_key_data = public_key_info.subject_public_key.data.to_vec();

    PublicKeyType::from_oid_and_key(&algorithm_oid, public_key_data)
        .map_err(|e| CertificateError::UnsupportedAlgorithm(e))
}