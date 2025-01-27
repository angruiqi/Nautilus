# Benchmarks Overview

## Introduction

This folder contains the benchmark results for the crates in Nautilus. The benchmark tests are designed to measure the performance of various storage and service discovery operations, including memory usage, execution time, and efficiency across different configurations.

## Structure
Each CSV will have varying columns in the CSV, but there are some common elements to take note of 

| Column Name     | Description                                                   |
|----------------|---------------------------------------------------------------|
| `set_no`        | The benchmark iteration or test batch number                  |
| `iteration`     | The iteration count within a benchmark set                    |
| `method`        | The method or approach used for storage (e.g., memory, file)  |
| `time_taken`    | Time taken for the operation in nanoseconds                    |
| `memory_usage`  | Memory consumption during the operation in bytes              |

## Usage

To utilize this folder, go to any of the crates that contain benchmark tests and run :
```rust
cargo bench --all-features

```
This will load in the CSV files into the `Nautilus/benches`. A Jupyton notebook will be provided for data analysis and produce charts for easier reference to technical developers.