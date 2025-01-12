#[cfg(feature = "aes")]
use std::io::{BufWriter, Write};
#[cfg(feature = "aes")]
use std::net::TcpStream;
#[cfg(feature = "aes")]
use data_encryption::{Aes256GcmEncryption,StreamEncryption};
#[cfg(feature = "aes")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = vec![0u8; 16]; // AES-128 key
    let nonce = vec![0u8; 12];
    let aes = Aes256GcmEncryption::new(key.clone(), nonce.clone())
    .expect("Failed to create AES-256 GCM instance");


    // Connect to the target server (127.0.0.1 on port 8081)
    let stream = TcpStream::connect("127.0.0.1:8081")?;
    let mut writer = BufWriter::new(stream);

    // Create a stream of 1000 numbers
    let plaintext_stream = (1..=1000)
        .map(|number| format!("{}\n", number))
        .map(|num_str| num_str.into_bytes());

    // Encrypt and send each chunk through the stream
    for chunk in plaintext_stream {
        aes.encrypt_stream(chunk.as_slice(), &mut writer, &key, &nonce)?;
    }

    writer.flush()?; // Ensure all data is written
    Ok(())
}
#[cfg(not(feature = "aes"))]
fn main() {
    println!("Enable Aes Feature");
}
