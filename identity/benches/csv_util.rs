use std::fs::{create_dir_all, File};
use std::io::{Write, BufWriter};

pub fn write_csv_results(algorithm: &str, task: &str, data: Vec<(usize, u128)>) {
    let dir_path = format!("benches/benchmark_results/{}/", algorithm);
    let file_path = format!("{}{}.csv", dir_path, task);

    // Ensure the directory exists
    create_dir_all(&dir_path).expect("Failed to create benchmark results directory");

    // Create the CSV file
    let file = File::create(&file_path).expect("Failed to create CSV file");
    let mut writer = BufWriter::new(file);

    // Write CSV header
    writeln!(writer, "Input Size (bytes), Time Taken (ns)").expect("Failed to write header");

    // Write data rows
    for (input_size, time_taken) in data {
        writeln!(writer, "{}, {}", input_size, time_taken).expect("Failed to write data row");
    }

    println!("Results written to {}", file_path);
}