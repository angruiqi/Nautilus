// security\data_encryption\src\key_derive\argon2_key_derive.rs
#[cfg(feature = "argon")]
use argon2::{Argon2,Version, Params};
#[cfg(feature = "argon")]
use crate::{KeyDerivation,utils::generate_secure_salt};
#[cfg(feature="argon")]
use zeroize::Zeroize;

#[cfg(feature = "argon")]
pub struct Argon2KeyDerivation {
    pub memory_size_kb: u32,
    pub iterations: u32,
    pub parallelism: u32,
}
#[cfg(feature = "argon")]
impl Drop for Argon2KeyDerivation {
    fn drop(&mut self) {
        self.memory_size_kb.zeroize();
        self.iterations.zeroize();
        self.parallelism.zeroize();
    }
}
#[cfg(feature = "argon")]
impl KeyDerivation for Argon2KeyDerivation {
    type Error = String;

    fn derive_key(
        &self,
        password: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        if output_length > 1024 * 1024 {
            return Err("Output length exceeds maximum allowed size (1MB).".to_string());
        }

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                self.memory_size_kb,
                self.iterations,
                self.parallelism,
                Some(output_length),
            )
            .map_err(|e| format!("Argon2 parameter setup failed: {}", e))?,
        );

        // Generate a secure random salt
        let mut salt = generate_secure_salt(16);

        // Initialize the output buffer for the derived key
        let mut derived_key = vec![0u8; output_length];

        // Perform the key derivation
        let result = argon2.hash_password_into(password, &salt, &mut derived_key);
        salt.zeroize(); // Zeroize salt after use

        if let Err(err) = result {
            derived_key.zeroize(); // Zero out the derived key on failure
            return Err(format!("Argon2 key derivation failed: {}", err));
        }

        Ok(derived_key)
    }
}
#[cfg(feature = "argon")]
impl Argon2KeyDerivation {
  pub fn new(memory_size_kb: u32, iterations: u32, parallelism: u32) -> Result<Self, String> {
      if memory_size_kb > 1024 * 1024 {
          return Err("Memory size exceeds the limit of 1 GB".to_string());
      }
      if iterations == 0 {
          return Err("Iterations must be greater than zero".to_string());
      }
      if parallelism == 0 {
          return Err("Parallelism must be greater than zero".to_string());
      }
      Ok(Self {
          memory_size_kb,
          iterations,
          parallelism,
      })
  }
}
#[cfg(feature = "argon")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyDerivation;

    #[test]
    fn test_derive_key_basic() {
        let derivation = Argon2KeyDerivation::new(65536, 3, 1).expect("Failed to create Argon2 instance");
        let password = b"password";
        let key = derivation
            .derive_key(password, 32)
            .expect("Key derivation failed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2_different_salts() {
        let derivation = Argon2KeyDerivation::new(4096, 3, 1).expect("Failed to create Argon2 instance");
        let password = b"password";
        let key1 = derivation.derive_key(password, 32).expect("Key derivation failed");
        let key2 = derivation.derive_key(password, 32).expect("Key derivation failed");

        assert_ne!(key1, key2); // Keys derived with different salts should be different
    }

    #[test]
    fn test_derive_key_with_large_output_length() {
        let derivation = Argon2KeyDerivation::new(65536, 3, 1).expect("Failed to create Argon2 instance");
        let password = b"password";
        let key = derivation
            .derive_key(password, 1024) // Large output length
            .expect("Key derivation failed");
        assert_eq!(key.len(), 1024);
    }

    #[test]
    fn test_argon2_empty_password_and_salt() {
        let derivation = Argon2KeyDerivation::new(4096, 3, 1).expect("Failed to create Argon2 instance");
        let password = b"";
        let key = derivation.derive_key(password, 32).expect("Key derivation failed");

        assert_eq!(key.len(), 32); // Ensure output length matches requested size
    }

    #[test]
    fn test_argon2_large_memory() {
        let derivation = Argon2KeyDerivation::new(64 * 1024, 3, 1).expect("Failed to create Argon2 instance"); // 64 MB
        let password = b"password";
        let key = derivation.derive_key(password, 32).expect("Key derivation failed");

        assert_eq!(key.len(), 32);
    }
}