use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=native/macos/eivro.m");
    println!("cargo:rerun-if-changed=native/macos/eivro.h");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    // Linux can type-check the Rust port. Linking a distributable still requires
    // Apple's SDK and the real bridge; no substitute implementation is linked.
    if !env::var("HOST").unwrap().contains("apple-darwin") {
        println!("cargo:warning=macOS Rust type-check only: native bridge must be built on macOS");
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let architecture = if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "aarch64" {
        "arm64"
    } else {
        "x86_64"
    };
    let status = Command::new("xcrun")
        .args([
            "clang",
            "-c",
            "-fobjc-arc",
            "-fblocks",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-mmacosx-version-min=26.0",
            "-arch",
            architecture,
            "native/macos/eivro.m",
            "-o",
        ])
        .arg(out.join("eivro.o"))
        .status()
        .unwrap();
    assert!(status.success(), "macOS native bridge compilation failed");
    assert!(
        Command::new("xcrun")
            .args(["ar", "crs"])
            .arg(out.join("libeivro_native.a"))
            .arg(out.join("eivro.o"))
            .status()
            .unwrap()
            .success()
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=eivro_native");
    for framework in ["AppKit", "Foundation", "SystemConfiguration", "Security"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
