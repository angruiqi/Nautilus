use async_trait::async_trait;
use crate::traits::connection::Connection;
use identity::KeyExchange;
use data_encryption::SymmetricEncryption;
#[async_trait]
pub trait SecureConnection<KEM, Cipher>: Connection
where
    KEM: KeyExchange,
    Cipher: SymmetricEncryption,
{
    /// Performs a handshake to establish a shared secret for secure communication.
    async fn perform_handshake(
        &mut self,
        local_keypair: KEM,
        peer_public_key: Option<KEM::PublicKey>, // Peer public key for KEM
    ) -> Result<(), Self::Error>;

    /// Encrypts data before sending using the provided cipher.
    fn encrypt(&self, cipher: &Cipher, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Decrypts received data using the provided cipher.
    fn decrypt(&self, cipher: &Cipher, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Checks if the connection is secure (e.g., handshake completed).
    fn is_secure(&self) -> bool;
}
