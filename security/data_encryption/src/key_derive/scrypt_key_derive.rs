// ================================ Data Encryption Module =======================
// security\data_encryption\src\key_derive\scrypt_key_derive.rs
#[cfg(feature = "scrypt_derive")]
use scrypt::{scrypt, Params};
#[cfg(feature = "scrypt_derive")]
use crate::{KeyDerivation, utils::generate_secure_salt};

// ========================= Scrypt Struct =========================
#[cfg(feature = "scrypt_derive")]
pub struct Scrypt {
    pub params: Params,
}

// ========================= KeyDerivation Trait Implementation =========================
#[cfg(feature = "scrypt_derive")]
impl KeyDerivation for Scrypt {
    type Error = String;

    fn derive_key(
        &self,
        password: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        if output_length > 1024 * 1024 {
            return Err("Output length exceeds the maximum allowed size (1MB).".to_string());
        }

        let salt = &generate_secure_salt(16);
        let mut key = vec![0u8; output_length];
        scrypt(password, salt, &self.params, &mut key).map_err(|e| e.to_string())?;
        Ok(key)
    }
}

// ============================================================================
