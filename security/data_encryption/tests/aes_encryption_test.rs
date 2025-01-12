#[cfg(feature = "aes")]
mod tests {
  use data_encryption::{Aes256GcmEncryption,SymmetricEncryption,StreamEncryption};
  use std::fs::File;
  use std::io::{BufReader, BufWriter, Cursor, Read, Write};
  use tempfile::tempdir;
  const KEY: [u8; 32] = [0u8; 32]; // AES-256 key
  const NONCE: [u8; 12] = [1u8; 12]; // AES nonce

  #[test]
  fn test_aes256_gcm_encrypt_decrypt() {
      let key = KEY.to_vec();
      let nonce = NONCE.to_vec();
      let data = b"Hello, AES-256 GCM!".to_vec();

      let aes = Aes256GcmEncryption::new(key.clone(), nonce.clone())
          .expect("Failed to create AES-256 GCM instance");

      let encrypted = aes.encrypt(&data).expect("Encryption failed");
      assert_ne!(data, encrypted);

      let decrypted = aes.decrypt(&encrypted).expect("Decryption failed");
      assert_eq!(data, decrypted);
  }

  #[test]
  fn test_invalid_key_length() {
      let invalid_key = vec![0u8; 16]; // Invalid key length
      let result = Aes256GcmEncryption::new(invalid_key, NONCE.to_vec());
      assert!(result.is_err());
      assert_eq!(result.err().unwrap(), "Invalid key length: expected 32 bytes, got 16");
  }

  #[test]
  fn test_invalid_nonce_length() {
      let invalid_nonce = vec![0u8; 10]; // Invalid nonce length
      let result = Aes256GcmEncryption::new(KEY.to_vec(), invalid_nonce);
      assert!(result.is_err());
      assert_eq!(result.err().unwrap(), "Invalid nonce length: expected 12 bytes.");
  }

  #[test]
  fn test_decrypt_with_wrong_key() {
      let key = KEY.to_vec(); // Original key
      let wrong_key = vec![1u8; 32]; // Different key
      let nonce = NONCE.to_vec();
      let data = b"Sensitive data!".to_vec();

      let aes_encryptor = Aes256GcmEncryption::new(key.clone(), nonce.clone())
          .expect("Failed to create AES-256 GCM instance");
      let aes_decryptor = Aes256GcmEncryption::new(wrong_key, nonce.clone())
          .expect("Failed to create AES-256 GCM instance");

      let encrypted = aes_encryptor.encrypt(&data).expect("Encryption failed");
      let result = aes_decryptor.decrypt(&encrypted);

      assert!(result.is_err());
  }
  #[test]
  fn test_decrypt_with_wrong_nonce() {
      let key = KEY.to_vec();
      let nonce = NONCE.to_vec();
      let wrong_nonce = vec![2u8; 12]; // Different nonce to ensure failure
      let data = b"Sensitive data!".to_vec();
  
      let aes_encryptor = Aes256GcmEncryption::new(key.clone(), nonce.clone())
          .expect("Failed to create AES-256 GCM instance");
      let aes_decryptor = Aes256GcmEncryption::new(key.clone(), wrong_nonce)
          .expect("Failed to create AES-256 GCM instance");
  
      let encrypted = aes_encryptor.encrypt(&data).expect("Encryption failed");
      let result = aes_decryptor.decrypt(&encrypted);
  
      // Validate decryption failure
      assert!(
          result.is_err(),
          "Decryption with a wrong nonce should fail, but it succeeded."
      );
  
      // Adjust to match the actual error message
      if let Err(err) = result {
          eprintln!("Decryption failed as expected with error: {}", err);
          assert_eq!(
              err, "aead::Error",
              "Unexpected error message: expected 'aead::Error'."
          );
      }
  }
  

  #[test]
  fn test_encrypt_empty_data() {
      let key = KEY.to_vec();
      let nonce = NONCE.to_vec();
      let data = b"".to_vec(); // Empty data

      let aes = Aes256GcmEncryption::new(key, nonce)
          .expect("Failed to create AES-256 GCM instance");

      let encrypted = aes.encrypt(&data).expect("Encryption failed");
      assert!(!encrypted.is_empty());

      let decrypted = aes.decrypt(&encrypted).expect("Decryption failed");
      assert_eq!(data, decrypted);
  }

  fn setup_aes() -> Aes256GcmEncryption {
      Aes256GcmEncryption::new(KEY.to_vec(), NONCE.to_vec())
          .expect("Failed to create AES-256 GCM instance")
  }

  #[test]
  fn test_stream_encryption_with_memory_streams() {
      let aes = setup_aes();
      let plaintext = b"Hello, Stream Encryption!";

      let mut input = Cursor::new(plaintext.to_vec());
      let mut encrypted_output = Vec::new();

      aes.encrypt_stream(&mut input, &mut encrypted_output, &KEY, &NONCE)
          .expect("Encryption failed");

      let mut encrypted_input = Cursor::new(encrypted_output);
      let mut decrypted_output = Vec::new();

      aes.decrypt_stream(&mut encrypted_input, &mut decrypted_output, &KEY, &NONCE)
          .expect("Decryption failed");

      assert_eq!(plaintext.to_vec(), decrypted_output);
  }

  #[test]
  fn test_stream_encryption_with_file_streams() {
      let aes = setup_aes();
      let plaintext = b"File-based streaming test.";
      let temp_dir = tempdir().expect("Failed to create temp dir");

      let input_file_path = temp_dir.path().join("plaintext.txt");
      let encrypted_file_path = temp_dir.path().join("encrypted.txt");
      let decrypted_file_path = temp_dir.path().join("decrypted.txt");

      // Write plaintext to a file
      let mut input_file = File::create(&input_file_path).expect("Failed to create input file");
      input_file.write_all(plaintext).expect("Failed to write plaintext");
      input_file.sync_all().expect("Failed to sync input file");

      // Encrypt
      let input_file = File::open(&input_file_path).expect("Failed to open input file");
      let mut encrypted_file =
          File::create(&encrypted_file_path).expect("Failed to create encrypted file");
      aes.encrypt_stream(
          BufReader::new(input_file),
          BufWriter::new(&mut encrypted_file),
          &KEY,
          &NONCE,
      )
      .expect("Encryption failed");

      // Decrypt
      let encrypted_file = File::open(&encrypted_file_path).expect("Failed to open encrypted file");
      let mut decrypted_file =
          File::create(&decrypted_file_path).expect("Failed to create decrypted file");
      aes.decrypt_stream(
          BufReader::new(encrypted_file),
          BufWriter::new(&mut decrypted_file),
          &KEY,
          &NONCE,
      )
      .expect("Decryption failed");

      // Read decrypted content and compare
      let mut decrypted_content = Vec::new();
      let mut decrypted_file =
          File::open(&decrypted_file_path).expect("Failed to open decrypted file");
      decrypted_file
          .read_to_end(&mut decrypted_content)
          .expect("Failed to read decrypted file");

      assert_eq!(plaintext.to_vec(), decrypted_content);
  }

  #[test]
  fn test_empty_stream() {
      let aes = setup_aes();

      let mut input = Cursor::new(Vec::new());
      let mut encrypted_output = Vec::new();

      // Encrypt
      aes.encrypt_stream(&mut input, &mut encrypted_output, &KEY, &NONCE)
          .expect("Encryption failed");

      assert!(encrypted_output.is_empty(), "Encrypted output should be empty");

      let mut encrypted_input = Cursor::new(encrypted_output);
      let mut decrypted_output = Vec::new();

      // Decrypt
      aes.decrypt_stream(&mut encrypted_input, &mut decrypted_output, &KEY, &NONCE)
          .expect("Decryption failed");

      assert!(decrypted_output.is_empty(), "Decrypted output should be empty");
  }
}
