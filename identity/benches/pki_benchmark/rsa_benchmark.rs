use criterion::{Criterion, criterion_group, criterion_main};
use identity::{PKITraits, RSAkeyPair};
use std::time::Instant;
use crate::csv_util::write_csv_results;

fn benchmark_rsa_keypair(_c: &mut Criterion) {
    let mut timings = Vec::new();

    for iteration in 0..300 { // Run 300 iterations
        let start = Instant::now();
        let _ = RSAkeyPair::generate_key_pair().expect("Failed to generate KeyPair");
        let elapsed_time = start.elapsed().as_nanos();
        timings.push((iteration + 1, elapsed_time)); // Store iteration index and time
    }

    write_csv_results("RSA", "keypair_generation", timings);
}

fn benchmark_rsa_sign_verify(_c: &mut Criterion) {
    let keypair = RSAkeyPair::generate_key_pair().expect("Failed to generate KeyPair");

    for size in [512, 1024, 2048, 4096, 8096, 16192].iter() {
        let mut sign_timings = Vec::new();
        let mut verify_timings = Vec::new();
        let data = vec![0u8; *size];

        // Benchmark signing
        for iteration in 0..300 {
            let start = Instant::now();
            let _signature = keypair.sign(&data).expect("Signing failed");
            let elapsed_time = start.elapsed().as_nanos();
            sign_timings.push((iteration + 1, elapsed_time));
        }

        write_csv_results("RSA", &format!("sign_{}", size), sign_timings);

        // Benchmark verification
        let signature = keypair.sign(&data).expect("Signing failed");
        for iteration in 0..300 {
            let start = Instant::now();
            let _ = keypair.verify(&data, &signature).expect("Verification failed");
            let elapsed_time = start.elapsed().as_nanos();
            verify_timings.push((iteration + 1, elapsed_time));
        }

        write_csv_results("RSA", &format!("verify_{}", size), verify_timings);
    }
}


// Criterion group definition
criterion_group!(
    rsa_benchmarks,
    benchmark_rsa_keypair,
    benchmark_rsa_sign_verify
);
criterion_main!(rsa_benchmarks);