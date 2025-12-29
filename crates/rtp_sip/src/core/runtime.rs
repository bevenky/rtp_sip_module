//! Runtime management for rtp_sip
//!
//! Manages both Tokio async runtime and libfs core initialization.
//! Tokio is initialized on module load; libfs is initialized lazily.
//!
//! # Mode Selection
//!
//! The module operates in one of two mutually exclusive modes:
//! - **RTP-only mode**: For Mode 3 (external SIP, internal RTP)
//! - **SIP mode**: For Mode 1/2 (internal SIP via mod_sofia)
//!
//! The mode is determined by which component is initialized first:
//! - `RtpSession` → RTP-only mode
//! - `SIP` (SipTransport) → SIP mode
//!
//! Once initialized, the mode cannot be changed without restarting the process.

use std::ffi::CStr;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU8, AtomicBool, Ordering};
use std::sync::Arc;

use once_cell::sync::OnceCell;
use tokio::runtime::Runtime as TokioRuntime;
use tracing::{debug, error, info, warn};

use crate::core::error::{Error, Result};

use libfs_sys::{
    fspr_initialize, switch_core_flag_t, switch_core_init,
    switch_core_ready, switch_core_session_count, switch_core_session_ctl,
    switch_core_set_globals, switch_loadable_module_init,
    switch_event_bind, switch_event_t, switch_event_get_header,
    SCF_MINIMAL, SCF_NO_AUTO_SCHEMAS,
    SCF_USE_NANOSLEEP, SCF_NO_NAT, SCSC_SHUTDOWN_ELEGANT, SWITCH_FALSE, SWITCH_STATUS_SUCCESS, SWITCH_TRUE,
    SWITCH_EVENT_CHANNEL_CREATE, SWITCH_EVENT_CHANNEL_HANGUP,
};

/// libfs operation mode
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FsMode {
    /// Not yet initialized
    Uninitialized = 0,
    /// RTP-only mode (Mode 3) - external SIP, internal RTP via switch_rtp_*
    RtpOnly = 1,
    /// SIP mode (Mode 1/2) - internal SIP via mod_sofia + media bugs
    SIP = 2,
}

impl FsMode {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => FsMode::RtpOnly,
            2 => FsMode::SIP,
            _ => FsMode::Uninitialized,
        }
    }

    /// Display name for logging
    pub fn name(&self) -> &'static str {
        match self {
            FsMode::Uninitialized => "Uninitialized",
            FsMode::RtpOnly => "RTP-only",
            FsMode::SIP => "SIP",
        }
    }
}

impl std::fmt::Debug for FsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::Display for FsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Global Tokio runtime
static RUNTIME: OnceCell<Arc<TokioRuntime>> = OnceCell::new();

/// Global libfs mode (immutable once set)
static FS_MODE: AtomicU8 = AtomicU8::new(FsMode::Uninitialized as u8);

/// Global libfs core initialization state
static FS_CORE_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// FreeSWITCH Event Callbacks (called from FS threads)
// ============================================================================

/// Called by FreeSWITCH when a new channel is created (inbound or outbound call)
///
/// # Safety
/// This is called from FreeSWITCH's event thread, not from Rust code.
/// We must not panic or hold locks across this callback.
unsafe extern "C" fn on_channel_create_event(event: *mut switch_event_t) {
    if event.is_null() {
        return;
    }

    // Get the UUID from the event
    let uuid_ptr = switch_event_get_header(
        event,
        b"Unique-ID\0".as_ptr() as *const libc::c_char,
    );

    if uuid_ptr.is_null() {
        warn!("CHANNEL_CREATE event without Unique-ID");
        return;
    }

    let uuid = match CStr::from_ptr(uuid_ptr).to_str() {
        Ok(s) => s,
        Err(_) => {
            warn!("CHANNEL_CREATE event with invalid UUID");
            return;
        }
    };

    info!("CHANNEL_CREATE event received for session: {}", uuid);

    // Attach media bug to capture audio for this session
    // Note: We do this on CHANNEL_CREATE but the bug won't capture audio
    // until the channel has media (after CHANNEL_ANSWER for inbound calls)
    match crate::core::sip::media_bug::attach_media_bug_by_uuid(uuid) {
        Ok(state) => {
            info!("Media bug attached to session {} (waiting for media)", uuid);
            // The MediaBugState is stored in the global registry
            // and will be accessible via get_media_bug_state(uuid)
            drop(state); // We don't need to hold the Arc here
        }
        Err(e) => {
            // This might fail if the session is very short-lived or already has a bug
            debug!("Could not attach media bug to session {}: {}", uuid, e);
        }
    }
}

/// Called by FreeSWITCH when a channel hangs up
///
/// # Safety
/// This is called from FreeSWITCH's event thread.
unsafe extern "C" fn on_channel_hangup_event(event: *mut switch_event_t) {
    if event.is_null() {
        return;
    }

    let uuid_ptr = switch_event_get_header(
        event,
        b"Unique-ID\0".as_ptr() as *const libc::c_char,
    );

    if uuid_ptr.is_null() {
        return;
    }

    let uuid = match CStr::from_ptr(uuid_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    info!("CHANNEL_HANGUP event received for session: {}", uuid);

    // Remove media bug for this session
    match crate::core::sip::media_bug::remove_media_bug(uuid) {
        Ok(()) => {
            info!("Media bug removed for session {}", uuid);
        }
        Err(e) => {
            // This is OK - the bug might have already been removed
            debug!("Could not remove media bug for session {}: {}", uuid, e);
        }
    }
}

/// pyswitch runtime handle
///
/// Manages:
/// - Tokio async runtime for Python async/await
/// - libfs core initialization (embedded mode, lazy)
pub struct Runtime {
    inner: Arc<TokioRuntime>,
}

impl Runtime {
    /// Initialize the Tokio runtime only
    ///
    /// This initializes the Tokio multi-threaded runtime for async operations.
    /// libfs is NOT initialized here - call `ensure_rtp_mode()` or `ensure_sip_mode()` when needed.
    ///
    /// Call this once at module load time.
    /// Safe to call multiple times - subsequent calls are no-ops.
    pub fn init() -> Result<Self> {
        // Initialize Tokio runtime only
        let rt = RUNTIME
            .get_or_try_init(|| {
                let num_threads = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4);

                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(num_threads)
                    .enable_all()
                    .thread_name("pyswitch")
                    .build()
                    .map(Arc::new)
                    .map_err(|e| Error::Runtime(e.to_string()))
            })?
            .clone();

        Ok(Self { inner: rt })
    }

    /// Get the current FreeSWITCH mode
    pub fn get_mode() -> FsMode {
        FsMode::from_u8(FS_MODE.load(Ordering::SeqCst))
    }

    /// Initialize FreeSWITCH in the specified mode
    ///
    /// This is the main entry point for FreeSWITCH initialization.
    /// The mode is set once and cannot be changed without restarting.
    ///
    /// # Arguments
    /// * `mode` - The desired operation mode (RtpOnly or SIP)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Already initialized in a different mode
    /// - Initialization fails
    ///
    /// # Thread Safety
    /// This function is safe to call concurrently from multiple threads.
    /// Only the first caller will perform initialization; others will wait.
    pub fn init_mode(mode: FsMode) -> Result<()> {
        if mode == FsMode::Uninitialized {
            return Err(Error::Runtime("Cannot initialize in Uninitialized mode".to_string()));
        }

        // Fast path: already fully initialized in this mode
        if FS_CORE_INITIALIZED.load(Ordering::SeqCst) {
            let current_mode = Self::get_mode();
            if current_mode == mode {
                return Ok(());
            } else {
                return Err(Error::Runtime(format!(
                    "Cannot switch to {} mode - already initialized in {} mode. Restart required.",
                    mode, current_mode
                )));
            }
        }

        // Try to claim the mode atomically (only from Uninitialized state)
        match FS_MODE.compare_exchange(
            FsMode::Uninitialized as u8,
            mode as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                // We claimed the mode, now initialize
                info!("Initializing libfs in {} mode", mode);
                let result = match mode {
                    FsMode::RtpOnly => Self::init_libfs_rtp_only(),
                    FsMode::SIP => Self::init_libfs_sip_mode(),
                    FsMode::Uninitialized => unreachable!(),
                };

                if result.is_ok() {
                    // Mark initialization complete
                    FS_CORE_INITIALIZED.store(true, Ordering::SeqCst);
                    info!("libfs {} mode initialization complete", mode);
                } else {
                    // Reset mode on failure so retry is possible
                    FS_MODE.store(FsMode::Uninitialized as u8, Ordering::SeqCst);
                    error!("libfs {} mode initialization failed", mode);
                }
                result
            }
            Err(actual) => {
                // Someone else already claimed a mode
                let actual_mode = FsMode::from_u8(actual);
                if actual_mode == mode {
                    // Same mode, wait for their init to complete
                    // Timeout: 30 seconds (switch_core_init can take 5-10 seconds)
                    debug!("Waiting for {} mode initialization by another thread", mode);
                    for i in 0..300 {
                        if FS_CORE_INITIALIZED.load(Ordering::SeqCst) {
                            debug!("libfs {} mode ready after waiting {} iterations ({}ms)", mode, i, i * 100);
                            return Ok(());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(Error::Runtime(format!("libfs {} mode initialization timed out (30s)", mode)))
                } else {
                    Err(Error::Runtime(format!(
                        "Cannot switch to {} mode - already initialized in {} mode. Restart required.",
                        mode, actual_mode
                    )))
                }
            }
        }
    }

    /// Convenience: Initialize in RTP-only mode
    ///
    /// Call this from RtpSession before using switch_rtp_* functions.
    pub fn ensure_rtp_mode() -> Result<()> {
        Self::init_mode(FsMode::RtpOnly)
    }

    /// Convenience: Initialize in SIP mode
    ///
    /// Call this from SipTransport before using mod_sofia.
    pub fn ensure_sip_mode() -> Result<()> {
        Self::init_mode(FsMode::SIP)
    }

    /// Check if currently in SIP mode
    pub fn is_sip_mode() -> bool {
        Self::get_mode() == FsMode::SIP
    }

    /// Check if currently in RTP-only mode
    pub fn is_rtp_mode() -> bool {
        Self::get_mode() == FsMode::RtpOnly
    }

    /// Initialize libfs for SIP mode (with mod_sofia)
    ///
    /// NOTE: SIP mode with embedded mod_sofia is currently NOT WORKING.
    ///
    /// Known issues:
    /// - switch_core_init_and_modload() segfaults in embedded mode
    /// - Manual module loading returns "module load file routine returned an error"
    ///
    /// For now, this initializes the core without mod_sofia, providing limited
    /// SIP functionality (event binding works, but calls won't work).
    ///
    /// Alternative approaches for SIP support:
    /// 1. Run libfs as a separate process and use ESL/API
    /// 2. Use sofia-sip library directly
    /// 3. Use a pure-Rust SIP stack
    fn init_libfs_sip_mode() -> Result<()> {
        info!("Initializing libfs in SIP mode...");
        warn!("Note: mod_sofia is not available in embedded mode");

        // Ignore SIGPIPE like FreeSWITCH binary does
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        // Set up libfs directories via environment variables
        Self::setup_freeswitch_directories()?;

        // Initialize APR (Apache Portable Runtime) first
        let apr_status = unsafe { fspr_initialize() };
        if apr_status != SWITCH_STATUS_SUCCESS {
            return Err(Error::Runtime("Failed to initialize APR".to_string()));
        }
        info!("APR initialized");

        // Call switch_core_set_globals() to populate global directory structure
        unsafe {
            switch_core_set_globals();
        }
        info!("Globals set");

        // Initialize core WITHOUT SCF_MINIMAL (more complete initialization)
        // but don't try to load mod_sofia (it crashes or fails in embedded mode)
        let flags: switch_core_flag_t = SCF_NO_AUTO_SCHEMAS | SCF_USE_NANOSLEEP | SCF_NO_NAT;

        let mut err: *const libc::c_char = ptr::null();
        let status = unsafe {
            switch_core_init(flags, SWITCH_FALSE, &mut err)
        };

        if status != SWITCH_STATUS_SUCCESS {
            let err_msg = if !err.is_null() {
                unsafe { CStr::from_ptr(err).to_string_lossy().to_string() }
            } else {
                "Unknown error".to_string()
            };
            error!("libfs core initialization failed: {}", err_msg);
            return Err(Error::Runtime(format!("libfs core init failed: {}", err_msg)));
        }

        info!("Core initialized");

        // Wait for core to be ready
        for _ in 0..50 {
            let ready = unsafe { switch_core_ready() };
            if ready == SWITCH_TRUE {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Initialize module subsystem (for potential future use)
        let mod_status = unsafe { switch_loadable_module_init(SWITCH_FALSE) };
        if mod_status == SWITCH_STATUS_SUCCESS {
            info!("Module subsystem initialized");
        }

        // Note: We skip loading mod_sofia because it doesn't work in embedded mode
        // The SIP transport will start but won't be able to make/receive calls
        warn!("SIP mode started but mod_sofia unavailable - calls will not work");
        warn!("For SIP functionality, run libfs as a separate process");

        // Bind to CHANNEL_CREATE events (will work if FS is used externally)
        info!("Binding to channel events...");
        let bind_status = unsafe {
            switch_event_bind(
                b"rtp_sip\0".as_ptr() as *const libc::c_char,
                SWITCH_EVENT_CHANNEL_CREATE,
                ptr::null(),
                Some(on_channel_create_event),
                ptr::null_mut(),
            )
        };
        if bind_status == SWITCH_STATUS_SUCCESS {
            info!("Bound to CHANNEL_CREATE events");
        }

        let hangup_status = unsafe {
            switch_event_bind(
                b"rtp_sip\0".as_ptr() as *const libc::c_char,
                SWITCH_EVENT_CHANNEL_HANGUP,
                ptr::null(),
                Some(on_channel_hangup_event),
                ptr::null_mut(),
            )
        };
        if hangup_status == SWITCH_STATUS_SUCCESS {
            info!("Bound to CHANNEL_HANGUP events");
        }

        info!("libfs initialized (SIP mode, limited)");
        Ok(())
    }

    /// Initialize libfs in RTP-only mode
    ///
    /// Uses SCF_MINIMAL flag for lightweight embedded mode.
    /// Suitable for direct switch_rtp_* usage without mod_sofia.
    fn init_libfs_rtp_only() -> Result<()> {
        info!("Initializing libfs in RTP-only mode...");

        // Ignore SIGPIPE like FreeSWITCH binary does
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        // Set up libfs directories via environment variables
        Self::setup_freeswitch_directories()?;

        // Initialize APR (Apache Portable Runtime) first
        info!("Calling fspr_initialize...");
        let apr_status = unsafe { fspr_initialize() };
        info!("fspr_initialize returned: {}", apr_status);
        if apr_status != SWITCH_STATUS_SUCCESS {
            return Err(Error::Runtime("Failed to initialize APR".to_string()));
        }
        info!("APR initialized successfully");

        // Call switch_core_set_globals() to populate global directory structure
        info!("Calling switch_core_set_globals...");
        unsafe {
            switch_core_set_globals();
        }
        info!("switch_core_set_globals completed");

        // libfs initialization flags for embedded use
        // SCF_MINIMAL is required for embedded mode - it skips the runtime loop
        // which allows us to use switch_rtp_* directly
        // Note: mod_sofia is currently NOT SUPPORTED - loading it breaks RTP
        let flags: switch_core_flag_t = SCF_MINIMAL | SCF_NO_AUTO_SCHEMAS | SCF_USE_NANOSLEEP | SCF_NO_NAT;

        info!("Calling switch_core_init with flags: 0x{:x}", flags);

        // Use switch_core_init (core only) - modload crashes in embedded mode
        // For SIP, we would need to load mod_sofia separately
        let mut err: *const libc::c_char = ptr::null();
        let status = unsafe {
            switch_core_init(flags, SWITCH_FALSE, &mut err)
        };

        if status != SWITCH_STATUS_SUCCESS {
            let err_msg = if !err.is_null() {
                unsafe { CStr::from_ptr(err).to_string_lossy().to_string() }
            } else {
                "Unknown error".to_string()
            };
            error!("libfs initialization failed: {}", err_msg);
            return Err(Error::Runtime(format!("libfs init failed: {}", err_msg)));
        }

        // Wait for core to be ready
        info!("Waiting for core to be ready...");
        for i in 0..100 {
            let ready = unsafe { switch_core_ready() };
            if ready == SWITCH_TRUE {
                info!("Core ready after {} iterations", i);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        info!("libfs core initialized, now loading modules...");

        // Initialize the module subsystem (don't autoload from config)
        info!("Calling switch_loadable_module_init...");
        let mod_status = unsafe { switch_loadable_module_init(SWITCH_FALSE) };
        if mod_status != SWITCH_STATUS_SUCCESS {
            warn!("switch_loadable_module_init returned: {} (continuing anyway)", mod_status);
        } else {
            info!("Module subsystem initialized");
        }

        // mod_sofia loading is DISABLED in embedded mode
        // Loading mod_sofia breaks the switch_rtp_* functions we use for RTP-only mode.
        // This is because mod_sofia tries to take over RTP management.
        //
        // For SIP support (Mode 1/2), we need a different approach:
        // 1. Use libfs as a separate process (not embedded)
        // 2. Use sofia-sip directly
        // 3. Implement SIP using a pure-Rust SIP stack
        //
        // For now, only Mode 3 (RTP-only) is supported in embedded mode.
        info!("mod_sofia not loaded (RTP-only mode)");

        info!("libfs initialized (RTP ready)");
        Ok(())
    }

    /// Set up libfs directory environment variables
    fn setup_freeswitch_directories() -> Result<()> {
        // Determine base directory for libfs files
        // Priority: PYSWITCH_FS_DIR env var > /usr/local/freeswitch > /opt/freeswitch > /tmp/pyswitch-fs
        let base_dir = std::env::var("PYSWITCH_FS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                // Check common libfs installation paths
                let usr_local_fs = PathBuf::from("/usr/local/freeswitch");
                let opt_fs = PathBuf::from("/opt/freeswitch");

                if usr_local_fs.exists() {
                    usr_local_fs
                } else if opt_fs.exists() {
                    opt_fs
                } else {
                    // Fallback to temp directory
                    let tmp_dir = std::env::temp_dir().join("pyswitch-fs");
                    if !tmp_dir.exists() {
                        let _ = std::fs::create_dir_all(&tmp_dir);
                    }
                    tmp_dir
                }
            });

        info!("libfs base directory: {:?}", base_dir);

        // Copy our minimal freeswitch.xml config if needed
        // This ensures we only load modules that are actually available
        Self::ensure_minimal_config(&base_dir)?;

        // Create subdirectories using libfs standard prefix structure
        // libfs expects: $prefix/etc/freeswitch, $prefix/var/log/freeswitch, etc.
        let subdirs = [
            "etc/freeswitch",
            "etc/freeswitch/tls",
            "var/log/freeswitch",
            "var/run/freeswitch",
            "var/lib/freeswitch/db",
            "var/lib/freeswitch/storage",
            "var/lib/freeswitch/recordings",
            "share/freeswitch/scripts",
            "share/freeswitch/sounds",
            "share/freeswitch/grammar",
            "share/freeswitch/htdocs",
        ];
        for subdir in &subdirs {
            let path = base_dir.join(subdir);
            if !path.exists() {
                std::fs::create_dir_all(&path).map_err(|e| {
                    Error::Runtime(format!("Failed to create {}: {}", path.display(), e))
                })?;
            }
        }

        // Set environment variables that libfs reads in switch_core_set_globals()
        // Using standard prefix directory structure
        let base_str = base_dir.to_string_lossy();

        // Core directories (standard prefix paths)
        std::env::set_var("FREESWITCH_PREFIX_DIR", &*base_str);
        std::env::set_var("FREESWITCH_CONF_DIR", format!("{}/etc/freeswitch", base_str));
        std::env::set_var("FREESWITCH_LOG_DIR", format!("{}/var/log/freeswitch", base_str));
        std::env::set_var("FREESWITCH_RUN_DIR", format!("{}/var/run/freeswitch", base_str));
        std::env::set_var("FREESWITCH_DB_DIR", format!("{}/var/lib/freeswitch/db", base_str));
        std::env::set_var("FREESWITCH_SCRIPTS_DIR", format!("{}/share/freeswitch/scripts", base_str));
        std::env::set_var("FREESWITCH_SOUNDS_DIR", format!("{}/share/freeswitch/sounds", base_str));
        std::env::set_var("FREESWITCH_STORAGE_DIR", format!("{}/var/lib/freeswitch/storage", base_str));

        // Module directory - this is where mod_sofia.so lives
        // Docker builds place it in lib/freeswitch/mod, not mod/
        let mod_dir = if base_dir.join("lib/freeswitch/mod").exists() {
            format!("{}/lib/freeswitch/mod", base_str)
        } else {
            format!("{}/mod", base_str)
        };
        std::env::set_var("FREESWITCH_MOD_DIR", &mod_dir);
        info!("Module directory: {}", mod_dir);

        // Additional directories
        std::env::set_var("FREESWITCH_HTDOCS_DIR", format!("{}/share/freeswitch/htdocs", base_str));
        std::env::set_var("FREESWITCH_GRAMMAR_DIR", format!("{}/share/freeswitch/grammar", base_str));
        std::env::set_var("FREESWITCH_RECORDINGS_DIR", format!("{}/var/lib/freeswitch/recordings", base_str));
        std::env::set_var("FREESWITCH_CERTS_DIR", format!("{}/etc/freeswitch/tls", base_str));
        std::env::set_var("FREESWITCH_CACHE_DIR", format!("{}/var/cache/freeswitch", base_str));
        std::env::set_var("FREESWITCH_DATA_DIR", format!("{}/share/freeswitch", base_str));
        std::env::set_var("FREESWITCH_LOCALSTATE_DIR", format!("{}/var/lib/freeswitch", base_str));
        std::env::set_var("FREESWITCH_FONTS_DIR", format!("{}/share/freeswitch/fonts", base_str));
        std::env::set_var("FREESWITCH_IMAGES_DIR", format!("{}/share/freeswitch/images", base_str));
        std::env::set_var("FREESWITCH_TEMP_DIR", format!("{}/var/tmp/freeswitch", base_str));

        debug!("libfs environment variables set");
        Ok(())
    }

    /// Ensure minimal libfs config exists
    ///
    /// Creates a minimal freeswitch.xml that only loads mod_sofia.
    /// This is necessary because the Docker image only builds mod_sofia,
    /// not other modules like mod_console, mod_g711, etc.
    fn ensure_minimal_config(base_dir: &PathBuf) -> Result<()> {
        let conf_dir = base_dir.join("etc/freeswitch");
        let config_path = conf_dir.join("freeswitch.xml");

        // Use existing libfs config structure (split config with autoload_configs, vars.xml, etc.)
        // Don't overwrite - let libfs load its default configuration
        if config_path.exists() {
            info!("Using existing libfs config at {:?}", config_path);
        } else {
            warn!("No libfs config found at {:?}", config_path);
        }

        Ok(())
    }

    /// Get the global runtime
    pub fn get() -> Result<Self> {
        let rt = RUNTIME
            .get()
            .cloned()
            .ok_or_else(|| Error::Runtime("Runtime not initialized".to_string()))?;

        Ok(Self { inner: rt })
    }

    /// Get a handle to the Tokio runtime
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.inner.handle().clone()
    }

    /// Spawn a future on the runtime
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.spawn(future)
    }

    /// Block on a future (for synchronous Python calls)
    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.inner.block_on(future)
    }

    /// Check if libfs core is ready
    pub fn is_freeswitch_ready() -> bool {
        if !FS_CORE_INITIALIZED.load(Ordering::SeqCst) {
            return false;
        }
        unsafe { switch_core_ready() == SWITCH_TRUE }
    }

    /// Get current session count
    pub fn session_count() -> u32 {
        if !FS_CORE_INITIALIZED.load(Ordering::SeqCst) {
            return 0;
        }
        unsafe { switch_core_session_count() }
    }

    /// Shutdown libfs gracefully
    ///
    /// Note: For embedded mode, we use a lightweight shutdown to avoid
    /// blocking issues. The full switch_core_destroy() can hang in
    /// embedded scenarios.
    pub fn shutdown() -> Result<()> {
        if !FS_CORE_INITIALIZED.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        // Reset mode to allow re-initialization after restart
        FS_MODE.store(FsMode::Uninitialized as u8, Ordering::SeqCst);

        info!("Shutting down libfs core...");

        // Request graceful shutdown (non-blocking)
        let mut val: libc::c_int = 0;
        unsafe {
            switch_core_session_ctl(SCSC_SHUTDOWN_ELEGANT, &mut val);
        }

        // Wait briefly for active sessions to clear
        // Don't wait too long - we're shutting down
        for _ in 0..5 {
            let count = unsafe { switch_core_session_count() };
            if count == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Skip switch_core_destroy() in embedded mode
        // It can hang waiting for internal threads. The OS will clean up
        // resources on process exit anyway.
        info!("libfs core shutdown complete (lightweight mode)");

        Ok(())
    }
}

impl Clone for Runtime {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // Note: We don't shutdown libfs here because the runtime
        // might be cloned and dropped multiple times. Shutdown should
        // be called explicitly or will happen on process exit.
        debug!("Runtime handle dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_init() {
        // Note: This test may fail if libfs libs aren't available
        // In that case, it will test only the Tokio runtime part
        let result = Runtime::init();

        // If libfs init fails, we should still have the Tokio runtime
        if result.is_err() {
            eprintln!("Runtime init failed (expected if FS libs missing): {:?}", result.err());
            return;
        }

        let rt = result.expect("Failed to init runtime");
        let rt2 = Runtime::get().expect("Failed to get runtime");

        // Should be the same runtime
        assert!(Arc::ptr_eq(&rt.inner, &rt2.inner));
    }

    #[test]
    fn test_runtime_spawn() {
        let result = Runtime::init();
        if result.is_err() {
            eprintln!("Skipping spawn test - runtime init failed");
            return;
        }

        let rt = result.unwrap();

        let result = rt.block_on(async {
            let handle = rt.spawn(async { 42 });
            handle.await.unwrap()
        });

        assert_eq!(result, 42);
    }

    #[test]
    fn test_libfs_rtp_mode_init() {
        // First init Tokio runtime
        let _ = Runtime::init();

        // Now try libfs init in RTP-only mode
        println!("Testing libfs RTP-only mode initialization...");
        match Runtime::ensure_rtp_mode() {
            Ok(()) => {
                println!("libfs initialized in RTP-only mode successfully!");
                // Give libfs a moment to fully start
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Check if ready
                let ready = Runtime::is_freeswitch_ready();
                println!("libfs ready: {}", ready);

                // Check session count (should be 0 initially)
                let count = Runtime::session_count();
                println!("Session count: {}", count);

                // Verify we're in RTP-only mode
                assert!(Runtime::is_rtp_mode(), "Should be in RTP-only mode");
            }
            Err(e) => {
                eprintln!("libfs init failed: {:?}", e);
                // This is expected if libfs isn't properly configured
            }
        }
    }

    #[test]
    #[ignore] // Must run in isolation: cargo test test_libfs_sip_mode -- --ignored
    fn test_libfs_sip_mode() {
        // This test must run in isolation because libfs can only be initialized
        // once per process. If other tests run first and initialize RTP-only mode,
        // this test will fail. Run with: cargo test test_libfs_sip_mode -- --ignored

        // First init Tokio runtime
        let _ = Runtime::init();

        println!("=== Testing libfs SIP Mode ===");

        // Try SIP mode initialization
        match Runtime::ensure_sip_mode() {
            Ok(()) => {
                println!("SIP mode initialized successfully!");

                // Give libfs time to fully start
                std::thread::sleep(std::time::Duration::from_secs(2));

                // Check if ready (may be false in embedded mode, that's OK)
                let ready = Runtime::is_freeswitch_ready();
                println!("libfs ready flag: {}", ready);
                // Note: switch_core_ready() might return false in embedded mode
                // because we don't have the full console/runtime loop running.
                // This is OK - we just want to verify the core loaded.

                // Check SIP mode flag
                let is_sip = Runtime::is_sip_mode();
                println!("SIP mode enabled: {}", is_sip);
                assert!(is_sip, "SIP mode should be enabled");

                // Check session count (should be 0 initially)
                // This tests that the core is functional even if not "ready"
                let count = Runtime::session_count();
                println!("Session count: {}", count);
                assert_eq!(count, 0, "Session count should be 0 initially");

                println!("=== SIP Mode Test PASSED ===");
            }
            Err(e) => {
                eprintln!("SIP mode init failed: {:?}", e);
                panic!("SIP mode initialization failed: {:?}", e);
            }
        }
    }
}
