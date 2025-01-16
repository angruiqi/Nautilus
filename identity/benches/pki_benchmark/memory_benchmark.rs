use criterion::{Criterion, criterion_group, criterion_main};
use std::fs::{self, File};
use std::io::Write;
use sysinfo::{System};
use identity::PKITraits;
#[cfg(feature = "dilithium")]
use identity::DilithiumKeyPair;
#[cfg(feature = "pki_rsa")]
use identity::RSAkeyPair;
#[cfg(feature = "ecdsa")]
use identity::ECDSAKeyPair;
#[cfg(feature = "ed25519")]
use identity::Ed25519KeyPair;
#[cfg(feature = "falcon")]
use identity::FalconKeyPair;
#[cfg(feature = "kyber")]
use identity::KyberKeyPair;
#[cfg(feature = "secp256k1")]
use identity::SECP256K1KeyPair;
#[cfg(feature = "spincs")]
use identity::SPHINCSKeyPair;

/// Benchmark memory usage for a given key generation function.
fn benchmark_memory_usage(
    cipher_name: &str,
    generate_keypair: impl Fn() -> (),
    iterations: usize,
) {
    let folder = format!("benches/benchmark_results/memory_bench/{}", cipher_name);
    fs::create_dir_all(&folder).expect("Failed to create benchmark result directory");

    let file_path = format!("{}/memory_usage.csv", folder);
    let mut file = File::create(file_path).expect("Failed to create CSV file");
    writeln!(file, "Iteration,MemoryUsage(Bytes)").unwrap();

    let mut sys = System::new_all();

    for iteration in 0..iterations {
        sys.refresh_memory();
        let memory_before = sys.total_memory() - sys.free_memory();

        // Generate the key pair
        generate_keypair();

        sys.refresh_memory();
        let memory_after = sys.total_memory() - sys.free_memory();
        let memory_used = memory_after.saturating_sub(memory_before);

        writeln!(file, "{},{}", iteration + 1, memory_used).unwrap();
    }
}

/// Add benchmarks for all supported ciphers.
fn benchmark_all_memory_usage(c: &mut Criterion) {
    #[cfg(feature = "dilithium")]
    c.bench_function("Dilithium Memory", |b| {
        b.iter(|| benchmark_memory_usage("Dilithium", || {
            DilithiumKeyPair::generate_key_pair().unwrap();
        }, 300));
    });

    #[cfg(feature = "pki_rsa")]
    c.bench_function("RSA Memory", |b| {
        b.iter(|| benchmark_memory_usage("RSA", || {
            RSAkeyPair::generate_key_pair().unwrap();
        }, 300));
    });

    #[cfg(feature = "ecdsa")]
    c.bench_function("ECDSA Memory", |b| {
        b.iter(|| benchmark_memory_usage("ECDSA", || {
            ECDSAKeyPair::generate_key_pair().unwrap();
        }, 300));
    });

    #[cfg(feature = "ed25519")]
    c.bench_function("Ed25519 Memory", |b| {
        b.iter(|| benchmark_memory_usage("Ed25519", || {
            Ed25519KeyPair::generate_key_pair().unwrap();
        }, 300));
    });

    #[cfg(feature = "falcon")]
    c.bench_function("Falcon Memory", |b| {
        b.iter(|| benchmark_memory_usage("Falcon", || {
            FalconKeyPair::generate_key_pair().unwrap();
        }, 300));
    });

    #[cfg(feature = "kyber")]
    c.bench_function("Kyber Memory", |b| {
        b.iter(|| benchmark_memory_usage("Kyber", || {
            KyberKeyPair::generate_key_pair().unwrap();
        }, 300));
    });

    #[cfg(feature = "secp256k1")]
    c.bench_function("SECP256K1 Memory", |b| {
        b.iter(|| benchmark_memory_usage("SECP256K1", || {
            SECP256K1KeyPair::generate_key_pair().unwrap();
        }, 300));
    });

    #[cfg(feature = "spincs")]
    c.bench_function("SPHINCS+ Memory", |b| {
        b.iter(|| benchmark_memory_usage("SPHINCS", || {
            SPHINCSKeyPair::generate_key_pair().unwrap();
        }, 300));
    });
}

// Criterion group and main entry point
criterion_group!(memory_benchmarks, benchmark_all_memory_usage);
criterion_main!(memory_benchmarks);
