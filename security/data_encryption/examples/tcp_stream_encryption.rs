use std::io::{BufWriter, Write};
use std::net::TcpStream;
use data_encryption::{AesGcmEncryption, AesKeySize, StreamEncryption};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = vec![0u8; 16]; // AES-128 key
    let nonce = vec![0u8; 12];
    let aes = AesGcmEncryption::new(AesKeySize::Aes128, key.clone(), nonce.clone())?;

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