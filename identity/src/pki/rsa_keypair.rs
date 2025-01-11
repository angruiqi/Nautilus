// identity\src\pki\rsa_keypair.rs
#[cfg(feature = "pki_rsa")]
extern crate rsa as rsa_crate;
#[cfg(feature = "pki_rsa")]
use crate::{PKIError, PKITraits};
#[cfg(feature = "pki_rsa")]
use rsa_crate::{
    pkcs1v15::{SigningKey, VerifyingKey, Signature},
    signature::{RandomizedSigner, Verifier, SignatureEncoding},
    RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPublicKey,
};
#[cfg(feature = "pki_rsa")]
use sha2::Sha256;
#[cfg(feature = "pki_rsa")]
use rand_core::{OsRng,RngCore};
#[cfg(feature = "pki_rsa")]
use sha2::Digest;
#[cfg(feature = "pki_rsa")]
use crate::KeyExchange;
#[cfg(feature = "pki_rsa")]
use rsa::traits::PublicKeyParts;
#[cfg(feature = "pki_rsa")]
use rsa_crate::Oaep;

#[cfg(feature = "pki_rsa")]
#[derive(Clone)]
pub struct RSAkeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}


#[cfg(feature = "pki_rsa")]
impl PKITraits for RSAkeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| PKIError::KeyPairGenerationError(format!("Key generation failed: {}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let mut rng = OsRng;

        let signature = signing_key.sign_with_rng(&mut rng, data);

        Ok(signature.to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());

        let signature = Signature::try_from(signature)
            .map_err(|e| PKIError::VerificationError(format!("Invalid signature format: {}", e)))?;

        verifying_key
            .verify(data, &signature)
            .map(|_| true)
            .map_err(|e| PKIError::VerificationError(format!("Verification failed: {}", e)))
    }
    
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        // Assuming the public key is a fixed-size array, convert it to Vec<u8>
        self.public_key.to_pkcs1_der().expect("Failed to encode public key to PKCS#8 DER format").as_bytes().to_vec()
    }
    fn key_type() -> String {
        "RSA".to_string()
    }
}
impl KeyExchange for RSAkeyPair {
    type SharedSecretKey = Vec<u8>;
    type PublicKey = RsaPublicKey;
    type PrivateKey = RsaPrivateKey;
    type Error = PKIError;

    fn encapsulate(public_key: &Self::PublicKey, _context: Option<&[u8]>) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error> {
        // Generate a random session key (32 bytes)
        let mut session_key = [0u8; 32];
        OsRng.fill_bytes(&mut session_key);
    
        // Encrypt the session key using RSA-OAEP
        let padding = Oaep::new::<Sha256>();
        let ciphertext = public_key
            .encrypt(&mut OsRng, padding, &session_key)
            .map_err(|e| PKIError::KeyExchangeError(format!("RSA encryption failed: {}", e)))?;
    
        // Generate a validation tag (e.g., HMAC or hash)
        let mut hasher = Sha256::new();
        hasher.update(&session_key);
        let tag = hasher.finalize().to_vec();
    
        // Combine ciphertext and tag into a single output
        let mut combined_output = ciphertext.clone();
        combined_output.extend_from_slice(&tag);
    
        Ok((session_key.to_vec(), combined_output))
    }

    fn decapsulate(private_key: &Self::PrivateKey, combined_ciphertext: &[u8], _context: Option<&[u8]>) -> Result<Self::SharedSecretKey, Self::Error> {
        // Split the combined ciphertext into the actual ciphertext and the tag
        let rsa_ciphertext_length = private_key.size();
        if combined_ciphertext.len() < rsa_ciphertext_length {
            return Err(PKIError::KeyExchangeError("Ciphertext too short".to_string()));
        }
        let (ciphertext, tag) = combined_ciphertext.split_at(rsa_ciphertext_length);
    
        // Decrypt the RSA ciphertext to get the session key
        let padding = Oaep::new::<Sha256>();
        let session_key = private_key
            .decrypt(padding, ciphertext)
            .map_err(|e| PKIError::KeyExchangeError(format!("RSA decryption failed: {}", e)))?;
    
        // Recompute the validation tag
        let mut hasher = Sha256::new();
        hasher.update(&session_key);
        let expected_tag = hasher.finalize().to_vec();
    
        // Validate the tag
        if tag != expected_tag {
            return Err(PKIError::KeyExchangeError("Validation tag mismatch".to_string()));
        }
    
        Ok(session_key)
    }
    fn key_exchange_type() -> String {
        "RSA-OAEP".to_string()
    }
}
