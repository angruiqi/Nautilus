// Declare `csv_util` at the root since it is in the root of the `benches` directory
mod csv_util;

// Declare `pki_benchmark` and its submodules
mod pki_benchmark {
    #[cfg(feature = "pki_rsa")]
    pub mod rsa_benchmark; // Declare `rsa_benchmark` as a submodule

    pub mod memory_benchmark;
}

// Use `criterion_main` to define the entry point for the benchmarks
#[cfg(feature = "pki_rsa")]
criterion::criterion_main!(pki_benchmark::memory_benchmark::memory_benchmarks);
