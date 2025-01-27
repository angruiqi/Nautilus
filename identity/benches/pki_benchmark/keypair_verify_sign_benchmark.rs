// identity\benches\pki_benchmark\keypair_verify_sign_benchmark.rs
/// Purpose: This benchmark evaluates the performance of different cryptographic algorithms
/// in terms of signing and verifying operations on varying data sizes. The results, including
/// memory usage and time taken for each operation, are recorded for analysis.

use criterion::{Criterion, criterion_group, criterion_main};
use std::env;
use std::fs::OpenOptions;
use std::io::{Write, BufReader, BufRead};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use sysinfo::System;
use identity::PKITraits;

#[cfg(feature = "pki_rsa")]
use identity::RSAkeyPair;
#[cfg(feature = "ecdsa")]
use identity::ECDSAKeyPair;
#[cfg(feature = "ed25519")]
use identity::Ed25519KeyPair;
#[cfg(feature = "dilithium")]
use identity::DilithiumKeyPair;
#[cfg(feature = "falcon")]
use identity::FalconKeyPair;
#[cfg(feature = "secp256k1")]
use identity::SECP256K1KeyPair;
// #[cfg(feature = "spincs")]
// use identity::SPHINCSKeyPair;

const ITERATIONS: usize = 10;
const FILE_SIZES: &[usize] = &[1024, 2048, 4096, 8096];

/// Get the benchmark output directory as "Nautilus/benches"
fn get_benchmark_path() -> PathBuf {
    let mut path = env::current_dir().expect("Failed to get current directory");
    path.pop(); // Go from 'identity' to 'Nautilus'
    path.push("benches");
    path
}

/// Ensure the CSV file has proper headers to avoid duplication
fn ensure_headers(file_name: &str, headers: &str) {
    let file_path = get_benchmark_path().join(file_name);

    if let Ok(file) = OpenOptions::new().read(true).open(&file_path) {
        let reader = BufReader::new(file);
        if reader.lines().next().is_none() {
            let mut file = OpenOptions::new().create(true).append(true).open(file_path).expect("Failed to open CSV file");
            writeln!(file, "{}", headers).expect("Failed to write headers to CSV");
        }
    } else {
        let mut file = OpenOptions::new().create(true).append(true).open(file_path).expect("Failed to open CSV file");
        writeln!(file, "{}", headers).expect("Failed to write headers to CSV");
    }
}

/// Append benchmark results to CSV file
fn append_to_csv(file_name: &str, content: &str) {
    let file_path = get_benchmark_path().join(file_name);
    let mut file = OpenOptions::new().create(true).append(true).open(file_path).expect("Failed to open CSV file");
    writeln!(file, "{}", content).expect("Failed to write to CSV");
}

/// Benchmark signing and verification operations
/// 
/// This function measures the performance of signing and verification operations
/// across different file sizes and records the time taken and memory used.
/// 
/// # Arguments
///
/// * `cipher_name` - The name of the cryptographic algorithm being benchmarked.
/// * `generate_keypair` - A closure that generates a keypair for the algorithm.
fn benchmark_sign_verify<T, E>(cipher_name: &str, generate_keypair: impl Fn() -> Result<T, E>)
where
    T: PKITraits<KeyPair = T, Error = E> + 'static,
    E: std::error::Error + 'static,
{
    let mut sys = System::new_all();

    ensure_headers(
        "pki_verify_sign_benchmark.csv",
        "SetNo,Iteration,Algorithm,FileSize,SignTime_ns,VerifyTime_ns,Memory_Usage"
    );

    for set_no in 0..ITERATIONS {
        for &file_size in FILE_SIZES.iter() {
            let keypair = generate_keypair().expect("Failed to generate keypair");
            let data = vec![0u8; file_size];

            for iteration in 1..=10 {
                sys.refresh_memory();
                let memory_before = sys.total_memory() - sys.free_memory();

                // Measure signing time
                let start_time = std::time::Instant::now();
                let signature = keypair.sign(&data).expect("Signing failed");
                let sign_time = start_time.elapsed().as_nanos();

                // Measure verification time
                let start_time = std::time::Instant::now();
                keypair.verify(&data, &signature).expect("Verification failed");
                let verify_time = start_time.elapsed().as_nanos();

                sys.refresh_memory();
                let memory_after = sys.total_memory() - sys.free_memory();
                let memory_used = memory_after.saturating_sub(memory_before);

                // Store results to CSV file
                append_to_csv(
                    "pki_verify_sign_benchmark.csv",
                    &format!("{},{},{},{},{},{},{}", set_no, iteration, cipher_name, file_size, sign_time, verify_time, memory_used),
                );
            }
        }
    }

    println!("Completed {} sign/verify test. Waiting 10 seconds before next cipher...", cipher_name);
    sleep(Duration::from_secs(10));
}

/// Criterion benchmark function to test sign/verify operations for different algorithms sequentially
fn all_ciphers_benchmark(_c: &mut Criterion) {
    #[cfg(feature = "pki_rsa")]
    benchmark_sign_verify("RSA", || RSAkeyPair::generate_key_pair());

    #[cfg(feature = "ecdsa")]
    benchmark_sign_verify("ECDSA", || ECDSAKeyPair::generate_key_pair());

    #[cfg(feature = "ed25519")]
    benchmark_sign_verify("Ed25519", || Ed25519KeyPair::generate_key_pair());

    #[cfg(feature = "dilithium")]
    benchmark_sign_verify("Dilithium", || DilithiumKeyPair::generate_key_pair());

    #[cfg(feature = "falcon")]
    benchmark_sign_verify("Falcon", || FalconKeyPair::generate_key_pair());

    #[cfg(feature = "secp256k1")]
    benchmark_sign_verify("SECP256K1", || SECP256K1KeyPair::generate_key_pair());

    // #[cfg(feature = "spincs")]
    // benchmark_sign_verify("SPHINCS", || SPHINCSKeyPair::generate_key_pair());
}

/// Configure Criterion benchmark settings such as sample size and measurement duration
fn configure_criterion() -> Criterion {
    Criterion::default()
        .sample_size(10)  // Set minimum required sample size
        .warm_up_time(Duration::from_secs(1))  // Warm-up phase to stabilize performance
        .measurement_time(Duration::from_secs(2))  // Measurement duration per sample
}

criterion_group! {
    name = crypto_benchmarks;
    config = configure_criterion();
    targets = all_ciphers_benchmark
}
criterion_main!(crypto_benchmarks);
