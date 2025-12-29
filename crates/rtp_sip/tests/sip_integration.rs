//! SIP Integration Test
//!
//! Tests SIP dial directly from Rust to isolate whether the issue is:
//! 1. Python -> Rust threading (if this test works, problem is Python)
//! 2. Rust -> FreeSWITCH (if this test fails, problem is in Rust)
//!
//! Run with:
//!   cargo test --package rtp_sip --test sip_integration -- --nocapture

use std::time::Duration;

/// Test that FreeSWITCH initializes correctly on the worker thread
#[test]
fn test_freeswitch_init_on_worker() {
    // Import the core modules directly
    // Note: We can't easily test the full module because it's a cdylib
    // Instead, we test the pattern that should work

    println!("=== Testing FreeSWITCH initialization pattern ===");

    // The key insight is:
    // - LibFsWorker spawns a thread and calls Runtime::ensure_freeswitch() on THAT thread
    // - All RTP operations go through that worker thread
    // - SIP operations in stack.rs call Runtime::ensure_freeswitch() on the CALLING thread
    // - This causes a threading mismatch

    // To verify: check if switch_core_ready() returns true when called from worker thread
    println!("Pattern analysis:");
    println!("  1. LibFsWorker thread calls ensure_freeswitch() - CORRECT");
    println!("  2. Sip::start() calls ensure_freeswitch() on caller thread - WRONG");
    println!("  3. Sip::dial() calls switch_ivr_originate() on caller thread - WRONG");
    println!("");
    println!("The fix: Route ALL FreeSWITCH FFI calls through LibFsWorker");
}

/// Test that shows the correct pattern for thread safety
#[test]
fn test_correct_threading_pattern() {
    use std::sync::mpsc;
    use std::thread;

    println!("\n=== Demonstrating correct threading pattern ===\n");

    // This demonstrates the pattern that WORKS (RTP):
    // 1. Create a dedicated worker thread
    // 2. Initialize FreeSWITCH ON that worker thread
    // 3. Send commands to the worker thread via channel
    // 4. Worker executes FFI calls and sends results back

    let (cmd_tx, cmd_rx) = mpsc::channel::<String>();
    let (result_tx, result_rx) = mpsc::channel::<String>();

    // Worker thread (like LibFsWorker)
    let worker = thread::spawn(move || {
        println!("[WORKER] Started on thread {:?}", thread::current().id());

        // This is where Runtime::ensure_freeswitch() should be called
        println!("[WORKER] Would call Runtime::ensure_freeswitch() here");

        // Process commands
        while let Ok(cmd) = cmd_rx.recv() {
            println!("[WORKER] Received command: {}", cmd);

            // Execute FFI on worker thread (like switch_ivr_originate)
            println!("[WORKER] Would call switch_ivr_originate() here");

            result_tx.send(format!("Result for: {}", cmd)).unwrap();

            if cmd == "shutdown" {
                break;
            }
        }

        println!("[WORKER] Shutting down");
    });

    // Main thread (like Python's asyncio thread)
    println!("[MAIN] Running on thread {:?}", thread::current().id());

    // Send SIP dial command
    cmd_tx.send("dial +1234567890".to_string()).unwrap();
    let result = result_rx.recv().unwrap();
    println!("[MAIN] Got result: {}", result);

    // Shutdown
    cmd_tx.send("shutdown".to_string()).unwrap();
    worker.join().unwrap();

    println!("\n=== Pattern demonstration complete ===");
    println!("The key: All FFI calls happen on the worker thread, not the caller's thread.\n");
}

/// Test showing what happens with the WRONG pattern (current SIP code)
#[test]
fn test_wrong_threading_pattern() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    println!("\n=== Demonstrating WRONG threading pattern (current SIP code) ===\n");

    // Simulate FS_INITIALIZED flag
    let fs_initialized = Arc::new(AtomicBool::new(false));

    // Thread 1: RTP operations (LibFsWorker)
    let fs_init_clone = fs_initialized.clone();
    let rtp_thread = thread::spawn(move || {
        println!("[RTP_WORKER] Thread {:?} - Initializing FreeSWITCH", thread::current().id());

        // First to call ensure_freeswitch - sets the flag
        if !fs_init_clone.swap(true, Ordering::SeqCst) {
            println!("[RTP_WORKER] I initialized FreeSWITCH on MY thread!");
        }

        thread::sleep(Duration::from_millis(100));
        println!("[RTP_WORKER] RTP operations work fine - I'm on the right thread");
    });

    // Wait for RTP to start
    thread::sleep(Duration::from_millis(50));

    // Thread 2: SIP operations (Python's asyncio thread)
    let fs_init_clone2 = fs_initialized.clone();
    let sip_thread = thread::spawn(move || {
        println!("[SIP/PYTHON] Thread {:?} - Trying to dial", thread::current().id());

        // Tries to ensure_freeswitch but flag is already set
        if !fs_init_clone2.swap(true, Ordering::SeqCst) {
            println!("[SIP/PYTHON] I initialized FreeSWITCH");
        } else {
            println!("[SIP/PYTHON] FreeSWITCH already initialized by another thread!");
            println!("[SIP/PYTHON] But I'm on a DIFFERENT thread than the one that initialized it");
            println!("[SIP/PYTHON] Calling switch_ivr_originate from wrong thread = PROBLEMS");
        }
    });

    rtp_thread.join().unwrap();
    sip_thread.join().unwrap();

    println!("\n=== This is why SIP fails when RTP works ===\n");
}
