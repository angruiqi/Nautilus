
#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use data_encryption::SymmetricCipherSuite;

    #[test]
    fn test_name() {
        #[cfg(feature = "aes")]
        assert_eq!(SymmetricCipherSuite::AES256GCM { priority: 1 }.name(), "AES256-GCM");

        #[cfg(feature = "blowfish")]
        assert_eq!(SymmetricCipherSuite::Blowfish { priority: 1 }.name(), "Blowfish");

        #[cfg(feature = "chacha20")]
        assert_eq!(SymmetricCipherSuite::ChaCha20 { priority: 1 }.name(), "ChaCha20");

        #[cfg(feature = "3des")]
        assert_eq!(SymmetricCipherSuite::TripleDES { priority: 1 }.name(), "TripleDES");
    }

    #[test]
    fn test_key_size() {
        #[cfg(feature = "aes")]
        assert_eq!(SymmetricCipherSuite::AES256GCM { priority: 1 }.key_size(), 32);

        #[cfg(feature = "blowfish")]
        assert_eq!(SymmetricCipherSuite::Blowfish { priority: 1 }.key_size(), 16);

        #[cfg(feature = "chacha20")]
        assert_eq!(SymmetricCipherSuite::ChaCha20 { priority: 1 }.key_size(), 32);

        #[cfg(feature = "3des")]
        assert_eq!(SymmetricCipherSuite::TripleDES { priority: 1 }.key_size(), 24);
    }

    #[test]
    fn test_nonce_size() {
        #[cfg(feature = "aes")]
        assert_eq!(SymmetricCipherSuite::AES256GCM { priority: 1 }.nonce_size(), 12);

        #[cfg(feature = "blowfish")]
        assert_eq!(SymmetricCipherSuite::Blowfish { priority: 1 }.nonce_size(), 0);

        #[cfg(feature = "chacha20")]
        assert_eq!(SymmetricCipherSuite::ChaCha20 { priority: 1 }.nonce_size(), 12);

        #[cfg(feature = "3des")]
        assert_eq!(SymmetricCipherSuite::TripleDES { priority: 1 }.nonce_size(), 8);
    }

}
