//! Build script for freeswitch-sys
//!
//! Supports two modes:
//! 1. EMBEDDED (default): Static linking from vendor/freeswitch-static
//! 2. SYSTEM: Dynamic linking to system-installed libfs
//!
//! Set FREESWITCH_DYNAMIC=1 to use system libfs instead of embedded.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=FREESWITCH_LIB_DIR");
    println!("cargo:rerun-if-env-changed=FREESWITCH_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=FREESWITCH_DYNAMIC");

    // Check if we should use dynamic linking
    let use_dynamic = env::var("FREESWITCH_DYNAMIC").is_ok();

    if use_dynamic {
        link_dynamic();
    } else {
        link_static();
    }
}

/// Link against static libfs libraries (embedded mode)
fn link_static() {
    // Find the vendor directory relative to this crate
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = PathBuf::from(&manifest_dir);

    // Try vendor/freeswitch-static first (built by scripts/build-freeswitch.sh)
    let vendor_static = manifest_path
        .parent() // crates/
        .unwrap()
        .parent() // pyswitch/
        .unwrap()
        .join("vendor")
        .join("freeswitch-static");

    let lib_dir = env::var("FREESWITCH_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| vendor_static.join("lib"));

    let include_dir = env::var("FREESWITCH_INCLUDE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| vendor_static.join("include"));

    // Check if static libs exist
    let libfreeswitch = lib_dir.join("libfreeswitch.a");
    if !libfreeswitch.exists() {
        eprintln!("=======================================================");
        eprintln!("ERROR: Static libfs libraries not found!");
        eprintln!("");
        eprintln!("Expected: {}", libfreeswitch.display());
        eprintln!("");
        eprintln!("To build embedded libfs:");
        eprintln!("  ./scripts/build-freeswitch.sh");
        eprintln!("");
        eprintln!("Or use system libfs:");
        eprintln!("  FREESWITCH_DYNAMIC=1 cargo build");
        eprintln!("=======================================================");

        // Fall back to dynamic linking for development
        eprintln!("");
        eprintln!("Falling back to dynamic linking for development...");
        link_dynamic();
        return;
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Link order matters for static libraries!
    // Libraries with more dependencies should come first

    // Use whole-archive for libfs to include all symbols (prevents dead code elimination)
    // This is critical because libfs uses function pointers and callbacks
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,--whole-archive");
    }

    // Static link libfs core (depends on sofia-sip, apr, etc.)
    println!("cargo:rustc-link-lib=static=freeswitch");

    // Static link sofiamod (sofia module - depends on freeswitch core)
    if lib_dir.join("libsofiamod.a").exists() {
        println!("cargo:rustc-link-lib=static=sofiamod");
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,--no-whole-archive");
    }

    // Static link sofia-sip (bundled with libfs)
    if lib_dir.join("libsofia-sip-ua.a").exists() {
        println!("cargo:rustc-link-lib=static=sofia-sip-ua");
    }

    // Static link spandsp (built from source)
    if lib_dir.join("libspandsp.a").exists() {
        println!("cargo:rustc-link-lib=static=spandsp");
    }

    // Static link SRTP (used by libfs for secure RTP)
    if lib_dir.join("libsrtp.a").exists() {
        println!("cargo:rustc-link-lib=static=srtp");
    }

    // Static link APR (Apache Portable Runtime - libfs uses fspr_ prefix for symbols)
    if lib_dir.join("libapr-1.a").exists() {
        println!("cargo:rustc-link-lib=static=apr-1");
    }
    if lib_dir.join("libaprutil-1.a").exists() {
        println!("cargo:rustc-link-lib=static=aprutil-1");
    }

    // Static link speex (bundled with libfs)
    if lib_dir.join("libspeex.a").exists() {
        println!("cargo:rustc-link-lib=static=speex");
    }
    if lib_dir.join("libspeexdsp.a").exists() {
        println!("cargo:rustc-link-lib=static=speexdsp");
    }

    // System libraries needed by libfs
    link_system_deps();

    // Set include path for headers
    if include_dir.exists() {
        println!(
            "cargo:include={}",
            include_dir.join("freeswitch").display()
        );
    }

    println!("cargo:warning=Using EMBEDDED libfs from {}", lib_dir.display());
}

/// Link against dynamic libfs libraries (system mode)
fn link_dynamic() {
    let freeswitch_lib = env::var("FREESWITCH_LIB_DIR")
        .unwrap_or_else(|_| "/usr/local/freeswitch/lib".to_string());

    println!("cargo:rustc-link-search=native={}", freeswitch_lib);
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu");

    // Dynamic link
    println!("cargo:rustc-link-lib=dylib=freeswitch");
    println!("cargo:rustc-link-lib=dylib=speexdsp");

    println!("cargo:warning=Using DYNAMIC libfs from {}", freeswitch_lib);
}

/// Link system dependencies required by libfs
fn link_system_deps() {
    // pthread
    println!("cargo:rustc-link-lib=pthread");

    // OpenSSL (usually available on system)
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");

    // Other common system libraries
    println!("cargo:rustc-link-lib=m");      // math
    println!("cargo:rustc-link-lib=dl");     // dynamic loading
    println!("cargo:rustc-link-lib=rt");     // realtime
    println!("cargo:rustc-link-lib=pcre");   // regex (used by libfs)
    println!("cargo:rustc-link-lib=z");      // zlib compression

    // libfs dependencies
    println!("cargo:rustc-link-lib=edit");   // editline/libedit
    println!("cargo:rustc-link-lib=curl");   // HTTP client
    println!("cargo:rustc-link-lib=sqlite3"); // database
    println!("cargo:rustc-link-lib=speex");  // audio codec
    println!("cargo:rustc-link-lib=speexdsp"); // audio DSP

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=uuid");
    }

    #[cfg(target_os = "macos")]
    {
        // macOS uses different libraries
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    }
}
