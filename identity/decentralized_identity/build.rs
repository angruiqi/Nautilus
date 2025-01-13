fn main() {
  let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

  if target_os == "windows" {
      println!("cargo:rustc-link-arg=/STACK:8388608");
  } else if target_os == "linux" {
      println!("cargo:rustc-link-arg=-Wl,-z,stack-size=8388608");
  }
}
