// utilities/certificate_parser/src/certificate_builder.rs
use crate::certificate_parsing_erorr::CertificateError;
use crate::CertificateType;
use base64::Engine as _ ;
/// A builder for constructing certificate generation parameters.
pub struct CertificateBuilder {
    pub subject_name: String,
    pub validity_days: u32,
    pub key_type: String,
    pub key_size: u32,
}

impl Default for CertificateBuilder {
    fn default() -> Self {
        Self {
            subject_name: "CN=DefaultCert".to_string(),
            validity_days: 365,
            key_type: "RSA".to_string(),
            key_size: 2048,
        }
    }
}

impl CertificateBuilder {
    /// Creates a new `CertificateBuilder` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the subject name for the certificate.
    pub fn subject_name(mut self, name: &str) -> Self {
        self.subject_name = name.to_string();
        self
    }

    /// Sets the validity period for the certificate in days.
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Sets the key type for the certificate (e.g., RSA, ECDSA).
    pub fn key_type(mut self, key_type: &str) -> Self {
        self.key_type = key_type.to_string();
        self
    }

    /// Sets the key size for the certificate (e.g., 2048, 4096).
    pub fn key_size(mut self, key_size: u32) -> Self {
        self.key_size = key_size;
        self
    }

    fn validate_key_size(&self) -> Result<(), CertificateError> {
        if ![2048, 3072, 4096].contains(&self.key_size) {
            return Err(CertificateError::ValidationError(format!(
                "Invalid key size: {}. Supported sizes are 2048, 3072, 4096.",
                self.key_size
            )));
        }
        Ok(())
    }

    fn validate_key_type(&self) -> Result<(), CertificateError> {
        if !["RSA", "ECDSA"].contains(&self.key_type.as_str()) {
            return Err(CertificateError::ValidationError(format!(
                "Invalid key type: {}. Supported types are RSA and ECDSA.",
                self.key_type
            )));
        }
        Ok(())
    }

    /// Builds the certificate generation parameters as a formatted string.
    pub fn build(self) -> Result<String, CertificateError> {
        // Validate key size
        self.validate_key_size()?;
        
        // Validate key type
        self.validate_key_type()?;

        // Build the certificate string
        let certificate = format!(
            "Certificate with {} key, size {} bits, valid for {} days, subject: {}",
            self.key_type, self.key_size, self.validity_days, self.subject_name
        );

        Ok(certificate)
    }


    pub fn export(self, format: CertificateType) -> Result<Vec<u8>, CertificateError> {
        let certificate = self.build()?;

        match format {
            CertificateType::PEM => {
                let pem = format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                    base64::engine::general_purpose::STANDARD.encode(certificate)
                );
                Ok(pem.into_bytes())
            }
            CertificateType::DER => {
                // Direct binary format, no encoding needed
                Ok(certificate.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_with_default_values() {
        let builder = CertificateBuilder::new();
        let result = builder.build();
        assert!(result.is_ok(), "Failed to build certificate with default values");
    }

    #[test]
    fn test_builder_with_custom_subject_name() {
        let builder = CertificateBuilder::new().subject_name("CN=Custom");
        let result = builder.build();
        assert!(result.is_ok(), "Failed to build certificate with custom subject name");
    }

    #[test]
    fn test_builder_with_invalid_key_size() {
        let builder = CertificateBuilder::new().key_size(1024); // Assuming 1024 is invalid
        let result = builder.build();
        assert!(result.is_err(), "Builder should fail for invalid key size");
    }

    #[test]
    fn test_builder_with_valid_key_size() {
        let builder = CertificateBuilder::new().key_size(2048);
        let result = builder.build();
        assert!(result.is_ok(), "Failed to build certificate with valid key size");
    }

    #[test]
    fn test_export_pem_format() {
        let builder = CertificateBuilder::new()
            .subject_name("CN=Test PEM")
            .key_type("RSA")
            .key_size(2048)
            .validity_days(365);

        let result = builder.export(CertificateType::PEM);
        assert!(result.is_ok(), "Failed to export PEM format");
        let pem = String::from_utf8(result.unwrap()).unwrap();
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_export_der_format() {
        let builder = CertificateBuilder::new()
            .subject_name("CN=Test DER")
            .key_type("RSA")
            .key_size(2048)
            .validity_days(365);

        let result = builder.export(CertificateType::DER);
        assert!(result.is_ok(), "Failed to export DER format");
        let der = result.unwrap();
        assert!(!der.is_empty(), "DER output should not be empty");
    }

    #[test]
    fn test_builder_with_invalid_key_type() {
        let builder = CertificateBuilder::new().key_type("InvalidKey");
        let result = builder.build();
        assert!(result.is_err(), "Builder should fail for invalid key type");
    }

    #[test]
    fn test_builder_with_custom_validity_days() {
        let builder = CertificateBuilder::new().validity_days(730);
        let result = builder.build();
        assert!(result.is_ok(), "Failed to build certificate with custom validity days");
    }

    #[test]
    fn test_builder_with_long_subject_name() {
        let builder = CertificateBuilder::new().subject_name("CN=ThisIsAVeryLongSubjectNameForTestingPurposes");
        let result = builder.build();
        assert!(result.is_ok(), "Failed to build certificate with a long subject name");
    }

    #[test]
    fn test_export_with_empty_certificate() {
        let builder = CertificateBuilder::new().key_size(0); // Assume 0 key size generates no certificate
        let result = builder.export(CertificateType::PEM);
        assert!(result.is_err(), "Export should fail for empty certificate");
    }
}
