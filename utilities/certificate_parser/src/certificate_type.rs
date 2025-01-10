pub enum CertificateType {
  PEM,
  DER,
}

pub enum PublicKeyType {
  RSA(Vec<u8>, String),         // OID: 1.2.840.113549.1.1.1
  ECDSA(Vec<u8>, String),       // OID: 1.2.840.10045.2.1
  SECP256K1(Vec<u8>, String),   // Example OID
  Dilithium(Vec<u8>, String),   // PQC
  SPHINCSPlus(Vec<u8>, String), // PQC
  Falcon(Vec<u8>, String),      // PQC
  Kyber(Vec<u8>, String),       // PQC
}

impl PublicKeyType {
  /// Creates a new `PublicKeyType` from the OID and raw key data.
  pub fn from_oid_and_key(oid: &str, key_data: Vec<u8>) -> Result<Self, String> {
      match oid {
          "1.2.840.113549.1.1.1" => Ok(PublicKeyType::RSA(key_data, oid.to_string())),
          "1.2.840.10045.2.1" => Ok(PublicKeyType::ECDSA(key_data, oid.to_string())),
          "1.3.132.0.10" => Ok(PublicKeyType::SECP256K1(key_data, oid.to_string())), // Example OID
          "2.16.840.1.101.3.4.3.13" => Ok(PublicKeyType::Dilithium(key_data, oid.to_string())), // Placeholder OID
          "1.3.9999.5.5.1.5" => Ok(PublicKeyType::SPHINCSPlus(key_data, oid.to_string())), // Placeholder OID
          "1.3.6.1.4.1.11591.4.11" => Ok(PublicKeyType::Falcon(key_data, oid.to_string())), // Placeholder OID
          "1.3.6.1.4.1.2.267.11.4.4" => Ok(PublicKeyType::Kyber(key_data, oid.to_string())), // Placeholder OID
          _ => Err(format!("Unsupported OID: {}", oid)),
      }
  }

  /// Returns the OID for the public key type.
  pub fn oid(&self) -> &str {
      match self {
          PublicKeyType::RSA(_, oid) => oid,
          PublicKeyType::ECDSA(_, oid) => oid,
          PublicKeyType::SECP256K1(_, oid) => oid,
          PublicKeyType::Dilithium(_, oid) => oid,
          PublicKeyType::SPHINCSPlus(_, oid) => oid,
          PublicKeyType::Falcon(_, oid) => oid,
          PublicKeyType::Kyber(_, oid) => oid,
      }
  }

  /// Returns the raw key data.
  pub fn key_data(&self) -> &Vec<u8> {
      match self {
          PublicKeyType::RSA(key, _) => key,
          PublicKeyType::ECDSA(key, _) => key,
          PublicKeyType::SECP256K1(key, _) => key,
          PublicKeyType::Dilithium(key, _) => key,
          PublicKeyType::SPHINCSPlus(key, _) => key,
          PublicKeyType::Falcon(key, _) => key,
          PublicKeyType::Kyber(key, _) => key,
      }
  }
}