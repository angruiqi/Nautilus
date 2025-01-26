// identity\benches\pki_benchmark\keypair_serialization_benchmark.rs
/// Purpose : To Benchmark Serialization Functions
use criterion::{Criterion, criterion_group, criterion_main};
use std::env;
use std::fs::OpenOptions;
use std::io::{Write, BufReader, BufRead};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use sysinfo::System;
use identity::PKITraits;
use identity::KeySerialization;

// Conditionally import various cryptographic keypair structures based on feature flags
#[cfg(feature = "pki_rsa")]
use identity::RSAkeyPair;
#[cfg(feature = "ecdsa")]
use identity::ECDSAKeyPair;
#[cfg(feature = "ed25519")]
use identity::Ed25519KeyPair;
#[cfg(feature = "dilithium")]
use identity::DilithiumKeyPair;
#[cfg(feature = "kyber")]
use identity::KyberKeyPair;
#[cfg(feature = "secp256k1")]
use identity::SECP256K1KeyPair;

// Number of benchmark iterations
const ITERATIONS: usize = 10;

/// Returns the benchmark output directory as `Nautilus/benches`.
fn get_benchmark_path() -> PathBuf {
    let mut path = env::current_dir().expect("Failed to get current directory");
    path.pop(); // Move from `identity` to `Nautilus`
    path.push("benches");
    path
}

/// Ensures CSV file has headers to prevent duplicate entries.
///
/// # Arguments
///
/// * `file_name` - The name of the benchmark result file.
/// * `headers` - A string containing the CSV headers.
fn ensure_headers(file_name: &str, headers: &str) {
    let file_path = get_benchmark_path().join(file_name);

    if let Ok(file) = OpenOptions::new().read(true).open(&file_path) {
        let reader = BufReader::new(file);
        if reader.lines().next().is_none() {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(file_path)
                .expect("Failed to open CSV file");
            writeln!(file, "{}", headers).expect("Failed to write headers to CSV");
        }
    } else {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .expect("Failed to open CSV file");
        writeln!(file, "{}", headers).expect("Failed to write headers to CSV");
    }
}

/// Appends benchmark results to a CSV file.
///
/// # Arguments
///
/// * `file_name` - The name of the CSV file to store benchmark data.
/// * `content` - The benchmark data to be written in CSV format.
fn append_to_csv(file_name: &str, content: &str) {
    let file_path = get_benchmark_path().join(file_name);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Failed to open CSV file");
    writeln!(file, "{}", content).expect("Failed to write to CSV");
}

/// Benchmarks serialization/deserialization for cryptographic algorithms.
///
/// This function measures the time and memory consumption for serializing and deserializing keypairs.
///
/// # Arguments
///
/// * `cipher_name` - The name of the cryptographic algorithm.
/// * `generate_keypair` - A closure function to generate the keypair.
fn benchmark_serialization<T>(cipher_name: &str, generate_keypair: impl Fn() -> T)
where
    T: PKITraits + KeySerialization,
{
    let mut sys = System::new_all();

    // Ensure the CSV file has appropriate headers
    ensure_headers(
        "pki_serialization_benchmark.csv",
        "SetNo,Iteration,Algorithm,SerializeTime_ns,DeserializeTime_ns,Memory_Usage",
    );

    for set_no in 0..ITERATIONS {
        for iteration in 1..=10 {
            sys.refresh_memory();
            let memory_before = sys.total_memory() - sys.free_memory();

            let keypair = generate_keypair();

            // Measure serialization time
            let start_time = std::time::Instant::now();
            let serialized = keypair.to_bytes();
            let serialize_time = start_time.elapsed().as_nanos();

            // Measure deserialization time
            let start_time = std::time::Instant::now();
            let _ = T::from_bytes(&serialized).unwrap();
            let deserialize_time = start_time.elapsed().as_nanos();

            sys.refresh_memory();
            let memory_after = sys.total_memory() - sys.free_memory();
            let memory_used = memory_after.saturating_sub(memory_before);

            // Store results in the CSV file
            append_to_csv(
                "pki_serialization_benchmark.csv",
                &format!("{},{},{},{},{},{}", set_no, iteration, cipher_name, serialize_time, deserialize_time, memory_used),
            );
        }
    }

    println!(
        "Completed {} serialization benchmark. Waiting 10 seconds before next cipher...",
        cipher_name
    );
    sleep(Duration::from_secs(10));
}

/// Criterion benchmark function to test serialization/deserialization for different ciphers sequentially.
///
/// Each algorithm is conditionally compiled based on its feature flag.
fn all_ciphers_benchmark(_c: &mut Criterion) {
    #[cfg(feature = "pki_rsa")]
    benchmark_serialization("RSA", || RSAkeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "ecdsa")]
    benchmark_serialization("ECDSA", || ECDSAKeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "ed25519")]
    benchmark_serialization("Ed25519", || Ed25519KeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "dilithium")]
    benchmark_serialization("Dilithium", || DilithiumKeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "kyber")]
    benchmark_serialization("Kyber", || KyberKeyPair::generate_key_pair().unwrap());

    #[cfg(feature = "secp256k1")]
    benchmark_serialization("SECP256K1", || SECP256K1KeyPair::generate_key_pair().unwrap());
}

/// Criterion configuration with limited samples and measurement time.
///
/// The sample size and warm-up time are configured to ensure stable performance readings.
fn configure_criterion() -> Criterion {
    Criterion::default()
        .sample_size(10) // Set minimum required sample size
        .warm_up_time(Duration::from_secs(1)) // Warm-up phase to stabilize performance
        .measurement_time(Duration::from_secs(2)) // Measurement duration per sample
}

// Define the benchmark group and run it using Criterion
criterion_group! {
    name = crypto_benchmarks;
    config = configure_criterion();
    targets = all_ciphers_benchmark
}
criterion_main!(crypto_benchmarks);
