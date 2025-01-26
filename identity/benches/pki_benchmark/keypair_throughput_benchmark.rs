// identity\benches\pki_benchmark\keypair_throughput_benchmark.rs
/// Purpose: This benchmark tests the throughput of different cryptographic algorithms by measuring
/// the number of signing and verification operations that can be performed per second. 
/// The results, including memory usage, are logged to CSV files for further analysis.

use criterion::{Criterion, criterion_group, criterion_main};
use std::env;
use std::fs::OpenOptions;
use std::io::{Write, BufReader, BufRead};
use std::path::PathBuf;
use std::time::{Instant, Duration};
use sysinfo::System;
use identity::PKITraits;
use std::fmt::Debug;

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

const TEST_DURATION: Duration = Duration::from_secs(10);
const FILE_SIZE: usize = 4096;

/// Get benchmark output directory as "Nautilus/benches"
fn get_benchmark_path() -> PathBuf {
    let mut path = env::current_dir().expect("Failed to get current directory");
    path.pop(); // Go from 'identity' to 'Nautilus'
    path.push("benches");
    path
}

/// Check if the file already contains headers to avoid duplicate headers
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

/// Append benchmark results to CSV
fn append_to_csv(file_name: &str, content: &str) {
    let file_path = get_benchmark_path().join(file_name);
    let mut file = OpenOptions::new().create(true).append(true).open(file_path).expect("Failed to open CSV file");
    writeln!(file, "{}", content).expect("Failed to write to CSV");
}

/// Benchmark throughput for signing and verification
fn benchmark_throughput<T>(cipher_name: &str, generate_keypair: impl Fn() -> T)
where
    T: PKITraits + Clone,
    <T as PKITraits>::Error: Debug,  // Ensure the associated Error type implements Debug
{
    let mut sys = System::new_all();

    ensure_headers("pki_throughput_benchmark.csv", "Algorithm,SignOpsPerSec,VerifyOpsPerSec,Memory_Usage");

    let keypair = generate_keypair();
    let data = vec![0u8; FILE_SIZE];

    // Measure signing throughput
    let start_time = Instant::now();
    let mut sign_count = 0;
    while start_time.elapsed() < TEST_DURATION {
        let _ = keypair.sign(&data).unwrap();
        sign_count += 1;
    }
    let sign_throughput = sign_count as f64 / TEST_DURATION.as_secs_f64();

    // Measure verification throughput
    let signature = keypair.sign(&data).unwrap();
    let start_time = Instant::now();
    let mut verify_count = 0;
    while start_time.elapsed() < TEST_DURATION {
        let _ = keypair.verify(&data, &signature).unwrap();
        verify_count += 1;
    }
    let verify_throughput = verify_count as f64 / TEST_DURATION.as_secs_f64();

    sys.refresh_memory();
    let memory_used = sys.total_memory() - sys.free_memory();

    append_to_csv(
        "pki_throughput_benchmark.csv",
        &format!("{},{:.2},{:.2},{}", cipher_name, sign_throughput, verify_throughput, memory_used),
    );

    println!("Completed {} throughput benchmark.", cipher_name);
}

/// Criterion benchmark function to test throughput for different ciphers sequentially
fn all_ciphers_benchmark(_c: &mut Criterion) {
    #[cfg(feature = "pki_rsa")]
    benchmark_throughput("RSA", || RSAkeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "ecdsa")]
    benchmark_throughput("ECDSA", || ECDSAKeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "ed25519")]
    benchmark_throughput("Ed25519", || Ed25519KeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "dilithium")]
    benchmark_throughput("Dilithium", || DilithiumKeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "falcon")]
    benchmark_throughput("Falcon", || FalconKeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "secp256k1")]
    benchmark_throughput("SECP256K1", || SECP256K1KeyPair::generate_key_pair().unwrap());
}

/// Criterion configuration with limited samples and measurement time
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
