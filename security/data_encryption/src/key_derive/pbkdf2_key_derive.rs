// security\data_encryption\src\key_derive\pbkdf2_key_derive.rs
#[cfg(feature="pbkdf")]
use pbkdf2::pbkdf2_hmac;
#[cfg(feature="pbkdf")]
use sha2::Sha256;
#[cfg(feature="pbkdf")]
use crate::{KeyDerivation,utils::generate_secure_salt};
#[cfg(feature="pbkdf")]
use zeroize::Zeroize;
#[cfg(feature="pbkdf")]
pub struct PBKDF2 {
    pub iterations: u32,
}

#[cfg(feature = "pbkdf")]
impl Drop for PBKDF2 {
    fn drop(&mut self) {
        self.iterations.zeroize(); // Ensure iterations are zeroized on drop
    }
}
#[cfg(feature = "pbkdf")]
impl KeyDerivation for PBKDF2 {
    type Error = String;

    fn derive_key(
        &self,
        password: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        if self.iterations == 0 {
            return Err("Iterations must be greater than zero".to_string());
        }

        if output_length > 1024 * 1024 {
            return Err("Output length exceeds maximum allowed size (1MB).".to_string());
        }

        // Generate a secure random salt
        let mut salt = generate_secure_salt(16);

        // Initialize the output buffer for the derived key
        let mut key = vec![0u8; output_length];

        // Perform the key derivation
        pbkdf2_hmac::<Sha256>(password, &salt, self.iterations, &mut key);

        // Zeroize the salt after use
        salt.zeroize();

        Ok(key)
    }
}

#[cfg(feature = "pbkdf")]
impl PBKDF2 {
    /// Creates a new `PBKDF2` instance with validation.
    pub fn new(iterations: u32) -> Result<Self, String> {
        if iterations == 0 {
            return Err("Iterations must be greater than zero.".to_string());
        }
        Ok(Self { iterations })
    }
}

#[cfg(feature="pbkdf")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_basic() {
        let pbkdf2 = PBKDF2 { iterations: 1000 };
        let password = b"secure_password";
        let derived_key = pbkdf2.derive_key(password, 32).expect("Failed to derive key");

        assert_eq!(derived_key.len(), 32);
        assert_ne!(derived_key, vec![0u8; 32]); // Ensure the derived key is not all zeros
    }

    #[test]
    fn test_derive_key_with_empty_password() {
        let pbkdf2 = PBKDF2 { iterations: 1000 };
        let password = b"";
        let derived_key = pbkdf2.derive_key(password, 32).expect("Failed to derive key");

        assert_eq!(derived_key.len(), 32);
        assert_ne!(derived_key, vec![0u8; 32]);
    }

    #[test]
    fn test_derive_key_with_zero_iterations() {
        let pbkdf2 = PBKDF2 { iterations: 0 };
        let password = b"secure_password";
        let result = pbkdf2.derive_key(password, 32);

        assert!(result.is_err(), "Derivation should fail with zero iterations");
    }

    #[test]
    fn test_derive_key_with_large_output_length() {
        let pbkdf2 = PBKDF2 { iterations: 1000 };
        let password = b"secure_password";
        let derived_key = pbkdf2
            .derive_key(password, 1024)
            .expect("Failed to derive key");

        assert_eq!(derived_key.len(), 1024);
        assert_ne!(derived_key, vec![0u8; 1024]);
    }

}
