use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};
use crate::{certificate_type::PublicKeyType, certificate_parsing_erorr::CertificateError};
use crate::cert_util_trait::CertUtilsTrait;

pub struct PemUtils;

impl CertUtilsTrait for PemUtils {
    fn parse(cert_data: &[u8]) -> Result<Vec<u8>, CertificateError> {
        let (_, pem) = parse_x509_pem(cert_data)
            .map_err(|_| CertificateError::ParseError("Invalid PEM format".to_string()))?;
        Ok(pem.contents.to_vec())
    }

    fn validate(cert_data: &[u8]) -> Result<bool, CertificateError> {
        // Basic validation logic (e.g., check if the certificate data is non-empty)
        Ok(!cert_data.is_empty())
    }

    fn extract_public_key(cert_data: &[u8]) -> Result<PublicKeyType, CertificateError> {
        let raw_cert = Self::parse(cert_data)?;
        let (_, cert) = parse_x509_certificate(&raw_cert)
            .map_err(|_| CertificateError::ParseError("Failed to parse certificate".to_string()))?;

        // Extract OID and public key
        let public_key_info = cert.tbs_certificate.subject_pki;
        let algorithm_oid = public_key_info.algorithm.algorithm.to_string();
        let public_key_data = public_key_info.subject_public_key.data.to_vec();

        PublicKeyType::from_oid_and_key(&algorithm_oid, public_key_data)
            .map_err(|e| CertificateError::UnsupportedAlgorithm(e))
    }

    fn export(cert_data: &[u8]) -> Result<Vec<u8>, CertificateError> {
        Ok(cert_data.to_vec())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_extract_public_key_pem_rsa() {
        let pem_data = fs::read("test_assets/rsa_cert.pem").unwrap();
        let result = PemUtils::extract_public_key(&pem_data);
        assert!(result.is_ok(), "Failed to extract RSA public key from PEM");

        if let Ok(PublicKeyType::RSA(_, oid)) = result {
            assert_eq!(oid, "1.2.840.113549.1.1.1", "Incorrect OID for RSA");
        } else {
            panic!("Unexpected public key type");
        }
    }

    #[test]
    fn test_extract_public_key_pem_ecdsa() {
        let pem_data = fs::read("test_assets/ecdsa_cert.pem").unwrap();
        let result = PemUtils::extract_public_key(&pem_data);
        assert!(result.is_ok(), "Failed to extract ECDSA public key from PEM");

        if let Ok(PublicKeyType::ECDSA(_, oid)) = result {
            assert_eq!(oid, "1.2.840.10045.2.1", "Incorrect OID for ECDSA");
        } else {
            panic!("Unexpected public key type");
        }
    }

    #[test]
    fn test_invalid_pem() {
        let invalid_pem = b"-----BEGIN CERTIFICATE-----\nInvalid Data\n-----END CERTIFICATE-----";
        let result = PemUtils::extract_public_key(invalid_pem);
        assert!(result.is_err(), "Invalid PEM should fail");
    }
}
