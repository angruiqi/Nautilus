// identity\examples\identity_example.rs
use identity::{PKIError, PKITraits}; 
#[cfg(feature = "pki_rsa")]
use identity::RSAkeyPair;
#[cfg(feature = "pki_rsa")] 
fn rsa_keypair() -> Result<(), PKIError> {

  println!("Running RSA keypair example");
  // Generate a key pair
  let key_pair = RSAkeyPair::generate_key_pair()?;
  // Sample data to sign
  let data = b"Example data for signing";

  // Sign the data
  let signature = key_pair.sign(data)?;

  // Verify the signature
  let is_valid = key_pair.verify(data, &signature)?;

  // Print the results
  println!("Signature valid: {}", is_valid);

  Ok(())
}

#[cfg(feature = "secp256k1")]
use identity::SECP256K1KeyPair;
#[cfg(feature = "secp256k1")]
fn secp256k1_keypair()-> Result<(), PKIError> {
  println!("Running SECP256K1 keypair example");
  // Generate a key pair
  let key_pair = SECP256K1KeyPair::generate_key_pair()?;
  // Sample data to sign
  let data = b"Example data for signing";

  // Sign the data
  let signature = key_pair.sign(data)?;

  // Verify the signature
  let is_valid = key_pair.verify(data, &signature)?;

  // Print the results
  println!("Signature valid: {}", is_valid);

  Ok(())
}

#[cfg(feature = "ecdsa")]
use identity::ECDSAKeyPair;
#[cfg(feature = "ecdsa")]
fn ecdsa_keypair() -> Result<(), PKIError> {
  println!("Running ECDSA keypair example");
  // Generate a key pair
  let key_pair = ECDSAKeyPair::generate_key_pair()?;
  // Sample data to sign
  let data = b"Example data for signing";

  // Sign the data
  let signature = key_pair.sign(data)?;

  // Verify the signature
  let is_valid = key_pair.verify(data, &signature)?;

  // Print the results
  println!("Signature valid: {}", is_valid);

  Ok(())
}
#[cfg(feature = "ed25519")]
use identity::Ed25519KeyPair;
#[cfg(feature = "ed25519")]
fn ed25519_keypair() -> Result<(), PKIError> {
  println!("Running ED25519 keypair example");
  // Generate a key pair
  let key_pair = Ed25519KeyPair::generate_key_pair()?;
  // Sample data to sign
  let data = b"Example data for signing";

  // Sign the data
  let signature = key_pair.sign(data)?;

  // Verify the signature
  let is_valid = key_pair.verify(data, &signature)?;

  // Print the results
  println!("Signature valid: {}", is_valid);

  Ok(())
}
#[cfg(feature = "dilithium")]
use identity::DilithiumKeyPair;
#[cfg(feature = "dilithium")]
fn dilithium_keypair() -> Result<(), PKIError> {
  println!("Running Dilithium keypair example");
  // Generate a key pair
  let key_pair = DilithiumKeyPair::generate_key_pair()?;
  // Sample data to sign
  let data = b"Example data for signing";

  // Sign the data
  let signature = key_pair.sign(data)?;

  // Verify the signature
  let is_valid = key_pair.verify(data, &signature)?;

  // Print the results
  println!("Signature valid: {}", is_valid);

  Ok(())
}
#[cfg(feature = "spincs")]
use identity::SPHINCSKeyPair;
#[cfg(feature = "spincs")]
use std::time::Instant;
#[cfg(feature = "spincs")]
fn spincs_keypair() {
  let message = b"Hello, SPHINCS+ world!";
  
  // Start the timer
  let start = Instant::now();

  // Generate a SPHINCS+ key pair
  match SPHINCSKeyPair::generate_key_pair() {
      Ok(key_pair) => {
          println!("Key pair generated successfully!");

          // Measure time taken for key generation
          let elapsed_keygen = start.elapsed();
          println!("Time taken to generate key pair: {:?}", elapsed_keygen);

          // Sign the message
          let sign_start = Instant::now();
          match key_pair.sign(message) {
              Ok(signature) => {
                  println!("Message signed successfully!");

                  // Measure time taken for signing
                  let elapsed_sign = sign_start.elapsed();
                  println!("Time taken to sign the message: {:?}", elapsed_sign);

                  // Verify the signature
                  let verify_start = Instant::now();
                  match key_pair.verify(message, &signature) {
                      Ok(is_valid) => {
                          println!("Signature valid: {}", is_valid);

                          // Measure time taken for verification
                          let elapsed_verify = verify_start.elapsed();
                          println!("Time taken to verify the signature: {:?}", elapsed_verify);
                      }
                      Err(e) => eprintln!("Verification error: {}", e),
                  }
              }
              Err(e) => eprintln!("Signing error: {}", e),
          }
      }
      Err(e) => eprintln!("Key pair generation error: {}", e),
  }

  // Measure total time
  let total_elapsed = start.elapsed();
  println!("Total time taken for the SPHINCS+ operations: {:?}", total_elapsed);
}
#[cfg(feature="falcon")]
use identity::FalconKeyPair;
#[cfg(feature="falcon")]
fn falcon_keypair() {
  // Generate a new Falcon key pair
  let falcon_keypair = FalconKeyPair::generate_key_pair().expect("Failed to generate Falcon key pair");

  // Data to be signed
  let data = b"This is some data to be signed.";

  // Sign the data
  let signature = falcon_keypair
      .sign(data)
      .expect("Failed to sign data");
  println!("Signature: {:?}", signature);

  // Verify the signature
  let is_valid = falcon_keypair
      .verify(data, &signature)
      .expect("Failed to verify signature");
  println!("Signature valid: {}", is_valid);

  // Retrieve the public key
  let public_key = falcon_keypair.get_public_key_raw_bytes();
  println!("Public Key: {:?}", public_key);

  // Output the key type
  let key_type = FalconKeyPair::key_type();
  println!("Key Type: {}", key_type);
}


fn main(){
  #[cfg(feature = "pki_rsa")] 
  rsa_keypair().unwrap();
  #[cfg(feature = "secp256k1")]
  secp256k1_keypair().unwrap();
  #[cfg(feature = "ecdsa")]
  ecdsa_keypair().unwrap();
  #[cfg(feature = "ed25519")]
  ed25519_keypair().unwrap();
  #[cfg(feature = "dilithium")]
  dilithium_keypair().unwrap();
  #[cfg(feature = "spincs")]
  spincs_keypair();
  #[cfg(feature="falcon")]
  falcon_keypair();
}

