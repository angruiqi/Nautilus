
#[cfg(feature = "kyber")]
use fips203::ml_kem_1024::{EncapsKey, DecapsKey, KG,CipherText};
#[cfg(feature = "kyber")]
use fips203::traits::{KeyGen, SerDes};
#[cfg(feature = "kyber")]
use crate::{PKITraits, PKIError};
#[cfg(feature = "kyber")]
use crate::KeyExchange;
#[cfg(feature = "kyber")]
use fips203::traits::{Decaps,Encaps};
/// A struct to represent a key pair with encapsulation and decapsulation keys.
#[cfg(feature = "kyber")]
pub struct KyberKeypair {
    pub encaps_key: EncapsKey,
    pub decaps_key: DecapsKey,
}

/// Implementation of the PKITraits trait.
#[cfg(feature = "kyber")]
impl PKITraits for KyberKeypair {
    type KeyPair = KyberKeypair;
    type Error = PKIError;

    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let (encaps_key, decaps_key) = KG::try_keygen()
            .map_err(|e| PKIError::KeyPairGenerationError(format!("Key generation failed: {:?}", e)))?;
        Ok(KyberKeypair { encaps_key, decaps_key })
    }

    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(PKIError::SigningError("Signing not implemented for ML-KEM".to_string()))
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, Self::Error> {
        Err(PKIError::VerificationError("Verification not implemented for ML-KEM".to_string()))
    }

    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.encaps_key.clone().into_bytes().to_vec()
    }

    fn key_type() -> String {
        "ML-KEM-1024".to_string()
    }
}



/// Implementation of the KeyExchange trait.
#[cfg(feature = "kyber")]
impl KeyExchange for KyberKeypair {
  type SharedSecretKey = Vec<u8>;
  type Error = PKIError;

  fn encapsulate(public_key_bytes: &[u8]) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error> {
      let public_key: [u8; 1568] = public_key_bytes
          .try_into()
          .map_err(|_| PKIError::KeyExchangeError("Invalid public key length".to_string()))?;
      let encaps_key = EncapsKey::try_from_bytes(public_key)
          .map_err(|e| PKIError::KeyExchangeError(format!("Failed to deserialize public key: {:?}", e)))?;
      let (shared_secret, ciphertext) = encaps_key.try_encaps()
          .map_err(|e| PKIError::KeyExchangeError(format!("Encapsulation failed: {:?}", e)))?;
      Ok((shared_secret.into_bytes().to_vec(), ciphertext.into_bytes().to_vec()))
  }

  fn decapsulate(&self, ciphertext: &[u8]) -> Result<Self::SharedSecretKey, Self::Error> {
    let ciphertext_bytes: [u8; 1568] = ciphertext
        .try_into()
        .map_err(|_| PKIError::KeyExchangeError("Invalid ciphertext length".to_string()))?;
    let ciphertext = CipherText::try_from_bytes(ciphertext_bytes)
        .map_err(|e| PKIError::KeyExchangeError(format!("Failed to deserialize ciphertext: {:?}", e)))?;
    let shared_secret = self.decaps_key.try_decaps(&ciphertext)
        .map_err(|e| PKIError::KeyExchangeError(format!("Decapsulation failed: {:?}", e)))?;
    Ok(shared_secret.into_bytes().to_vec())
}
}


#[cfg(feature = "kyber")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let key_pair = KyberKeypair::generate_key_pair().expect("Key generation failed");
        let public_key = key_pair.get_public_key_raw_bytes();
        assert_eq!(public_key.len(), 1568);
        println!("Generated key pair successfully.");
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let key_pair = KyberKeypair::generate_key_pair().expect("Key generation failed");
        let public_key = key_pair.get_public_key_raw_bytes();

        // Test encapsulate
        let (shared_secret, ciphertext) = KyberKeypair::encapsulate(&public_key).expect("Encapsulation failed");
        assert_eq!(ciphertext.len(), 1568);
        println!("Encapsulation successful.");

        // Test decapsulate
        let recovered_secret = key_pair.decapsulate(&ciphertext).expect("Decapsulation failed");
        assert_eq!(shared_secret, recovered_secret);
        println!("Decapsulation successful. Shared secrets match.");
    }
}