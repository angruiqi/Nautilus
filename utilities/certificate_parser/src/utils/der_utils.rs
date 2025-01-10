use x509_parser::parse_x509_certificate;
use crate::{PublicKeyType, CertificateError};
use crate::cert_util_trait::CertUtilsTrait;

pub struct DerUtils;

impl CertUtilsTrait for DerUtils {
    fn parse(cert_data: &[u8]) -> Result<Vec<u8>, CertificateError> {
        Ok(cert_data.to_vec())
    }

    fn validate(cert_data: &[u8]) -> Result<bool, CertificateError> {
        // Basic validation logic
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
    fn test_extract_public_key_der_rsa() {
        let der_data = fs::read("test_assets/rsa_cert.der").unwrap();
        let result = DerUtils::extract_public_key(&der_data);
        assert!(result.is_ok(), "Failed to extract RSA public key from DER");

        if let Ok(PublicKeyType::RSA(_, oid)) = result {
            assert_eq!(oid, "1.2.840.113549.1.1.1", "Incorrect OID for RSA");
        } else {
            panic!("Unexpected public key type");
        }
    }

    #[test]
    fn test_extract_public_key_der_ecdsa() {
        let der_data = fs::read("test_assets/ecdsa_cert.der").unwrap();
        let result = DerUtils::extract_public_key(&der_data);
        assert!(result.is_ok(), "Failed to extract ECDSA public key from DER");

        if let Ok(PublicKeyType::ECDSA(_, oid)) = result {
            assert_eq!(oid, "1.2.840.10045.2.1", "Incorrect OID for ECDSA");
        } else {
            panic!("Unexpected public key type");
        }
    }

    #[test]
    fn test_invalid_der() {
        let invalid_der = vec![0x00, 0x01, 0x02];
        let result = DerUtils::extract_public_key(&invalid_der);
        assert!(result.is_err(), "Invalid DER should fail");
    }
}