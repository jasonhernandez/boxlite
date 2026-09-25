//! ShimController and ShimHandler - Universal process management for all Box engines.

use std::{path::PathBuf, process::Child, sync::Mutex, time::Instant};

use crate::{
    BoxID,
    runtime::layout::BoxFilesystemLayout,
    vmm::{InstanceSpec, VmmKind},
};

use boxlite_shared::errors::{BoxliteError, BoxliteResult};

use super::watchdog;
use super::{
    VmmController, VmmHandler as VmmHandlerTrait, VmmMetrics,
    spawn::{ShimSpawner, SpawnedShim},
};

// ============================================================================
// SHIM HANDLER - Runtime operations on running VM
// ============================================================================

/// Runtime handler for a running VM subprocess.
///
/// Provides lifecycle operations (stop, metrics, status) for a VM identified by PID.
/// Works for both spawned VMs and reconnected VMs (same operations).
pub struct ShimHandler {
    pid: u32,
    #[allow(dead_code)]
    box_id: BoxID,
    /// Child process handle for proper lifecycle management.
    /// When we spawn the process, we keep the Child to properly wait() on stop.
    /// When we attach to an existing process, this is None.
    process: Option<Child>,
    /// Watchdog keepalive. Dropping closes the pipe write end, delivering
    /// POLLHUP to the shim and triggering graceful shutdown.
    /// Defense-in-depth: even if `stop()` is never called, dropping the
    /// handler closes this, triggering shim cleanup automatically.
    #[allow(dead_code)]
    keepalive: Option<watchdog::Keepalive>,
    /// Shared System instance for CPU metrics calculation across calls.
    /// CPU usage requires comparing snapshots over time, so we must reuse the same System.
    metrics_sys: Mutex<sysinfo::System>,
}

impl ShimHandler {
    /// Create a handler from a spawned shim.
    ///
    /// Takes ownership of the `SpawnedShim` (child process + keepalive) for
    /// proper lifecycle management. The keepalive keeps the watchdog pipe
    /// alive; dropping it triggers shim shutdown.
    pub fn from_spawned(spawned: SpawnedShim, box_id: BoxID) -> Self {
        let pid = spawned.child.id();
        Self {
            pid,
            box_id,
            process: Some(spawned.child),
            keepalive: spawned.keepalive,
            metrics_sys: Mutex::new(sysinfo::System::new()),
        }
    }

    /// Create a handler for an existing VM (attach mode).
    ///
    /// Used when reconnecting to a running box. We don't have a Child handle
    /// or keepalive, so we manage the process by PID only.
    ///
    /// # Arguments
    /// * `pid` - Process ID of the running VM
    /// * `box_id` - Box identifier (for logging)
    pub fn from_pid(pid: u32, box_id: BoxID) -> Self {
        Self {
            pid,
            box_id,
            process: None,
            keepalive: None,
            metrics_sys: Mutex::new(sysinfo::System::new()),
        }
    }

    /// Graceful shutdown of the recorded process: SIGTERM, wait, then SIGKILL.
    ///
    /// Signals only `self.pid` (the outer launcher). The full process-tree
    /// sweep happens in `stop()` after this returns — see the comment there for
    /// why the order matters (libkrun must flush before the hard cgroup kill).
    fn graceful_stop(&mut self) -> BoxliteResult<()> {
        // Graceful shutdown: SIGTERM first, wait, then SIGKILL if needed.
        // This gives libkrun time to flush its virtio-blk buffers to disk,
        // preventing qcow2 corruption.
        const GRACEFUL_SHUTDOWN_TIMEOUT_MS: u64 = 2000;

        if let Some(mut process) = self.process.take() {
            // Step 1: Send SIGTERM for graceful shutdown
            let pid = process.id();
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }

            // Step 2: Wait with timeout for process to exit
            let start = std::time::Instant::now();
            loop {
                match process.try_wait() {
                    Ok(Some(_)) => {
                        // Process exited gracefully
                        return Ok(());
                    }
                    Ok(None) => {
                        // Still running, check timeout
                        if start.elapsed().as_millis() > GRACEFUL_SHUTDOWN_TIMEOUT_MS as u128 {
                            // Timeout - force kill
                            let _ = process.kill();
                            let _ = process.wait();
                            return Ok(());
                        }
                        // Brief sleep before checking again
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(_) => {
                        // Error checking status - try to kill anyway
                        let _ = process.kill();
                        let _ = process.wait();
                        return Ok(());
                    }
                }
            }
        } else {
            // Attached mode: we hold no Child, only a pid. Pin it with a
            // ProcessMonitor (a pidfd on Linux) BEFORE signalling, and do every
            // signal and wait through that. The same process may also run a
            // reaper thread for this launcher (a dropped handler's, see Drop),
            // which can reap it the instant it exits; after that the pid
            // number can be reused, and a bare waitpid/kill(pid) here could
            // then wait or SIGKILL an unrelated process.
            let monitor = crate::util::ProcessMonitor::new(self.pid);
            monitor.signal(libc::SIGTERM);

            // Poll for exit with timeout
            let start = std::time::Instant::now();
            loop {
                if monitor.try_wait().is_some() {
                    // Exited: reaped by us, or by its parent / reaper thread.
                    return Ok(());
                }

                if start.elapsed().as_millis() > GRACEFUL_SHUTDOWN_TIMEOUT_MS as u128 {
                    // Timeout - force kill
                    monitor.signal(libc::SIGKILL);
                    return Ok(());
                }

                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}

/// Stack for the thread that waits a dropped shim. It only ever sits in
/// `waitpid`, so the default 2 MiB would be pure address-space waste — and a
/// detached box keeps its thread for as long as the box runs.
const REAPER_STACK_BYTES: usize = 64 * 1024;

impl Drop for ShimHandler {
    /// Wait the spawned launcher even though nobody called `stop()`.
    ///
    /// This process forked the outer `bwrap`, so only this process can reap
    /// it, and `std::process::Child` does not wait on drop. A handler dropped
    /// without `stop()` therefore turns the launcher into a zombie the moment
    /// it exits — for the life of this process, since nothing else will ever
    /// `waitpid` that pid.
    ///
    /// That is the ordinary lifecycle of a *detached* box driven by a
    /// short-lived runtime: the runtime spawns the shim, hands back a handle,
    /// and is dropped (it must be — a runtime holds `BOXLITE_HOME`'s exclusive
    /// lock, so a long-lived host process cannot keep one open). Dropping the
    /// runtime cancels the box watcher, which is the only other thing that
    /// would have reaped the pid. The box is then stopped later from another
    /// process, the launcher exits, and it stays `<defunct>` under the host
    /// process forever: one per box, unbounded in the host's uptime.
    ///
    /// The wait is scoped to this one pid, which this handler alone spawned —
    /// never `waitpid(-1)`, so it cannot consume any other child's status. The
    /// only other waiters on the same pid are boxlite's own: the box watcher
    /// and `graceful_stop` in attach mode. Losing the race to this thread costs
    /// them the exit *code* (they record the guest's exit file instead, and
    /// report `ProcessExit::Unknown`), and it would also free the pid number
    /// for reuse while they still poll it. So both go through
    /// [`ProcessMonitor`](crate::util::ProcessMonitor), which pins the process
    /// with a pidfd when it is built and never trusts the bare number after
    /// that. On a system without pidfds (pre-5.3 kernels, macOS) they fall
    /// back to the number, and a reuse inside one 500 ms poll could make the
    /// watcher see a stranger as the running box.
    ///
    /// Blocking in a thread rather than a tokio task, because the runtime that
    /// owned this handler — and its cancellation token — may already be gone;
    /// a plain thread depends on neither. It lives exactly as long as the
    /// launcher does.
    fn drop(&mut self) {
        let Some(mut child) = self.process.take() else {
            return; // attached by pid, or already waited by stop()
        };
        match child.try_wait() {
            Ok(Some(_)) => {} // already exited: try_wait just reaped it
            Ok(None) => {
                let pid = self.pid;
                let spawned = std::thread::Builder::new()
                    .name(format!("boxlite-reap-{pid}"))
                    .stack_size(REAPER_STACK_BYTES)
                    .spawn(move || {
                        let _ = child.wait();
                    });
                if let Err(e) = spawned {
                    tracing::warn!(
                        pid,
                        error = %e,
                        "Could not start a thread to wait the shim launcher; \
                         it will stay a zombie after it exits"
                    );
                }
            }
            // ECHILD: somebody already reaped it. Nothing left to wait.
            Err(_) => {}
        }
    }
}

impl VmmHandlerTrait for ShimHandler {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn stop(&mut self) -> BoxliteResult<()> {
        // Graceful shutdown of the recorded pid first, then sweep the box's
        // whole tree. `graceful_stop` only signals the recorded pid — the outer
        // bwrap launcher — and a detached box's inner pid-ns tree (inner bwrap +
        // shim + VM) outlives it, since #851 stopped applying `--die-with-parent`
        // to detached boxes. The whole tree lives in the box's cgroup, so reap it
        // by id — *after* graceful shutdown, so libkrun can flush its virtio-blk
        // buffers first (a cgroup kill is a hard kill; reaping mid-flush risks
        // qcow2 corruption). Best-effort and idempotent.
        let result = self.graceful_stop();
        crate::jailer::reap_box(&self.box_id);
        result
    }

    fn metrics(&self) -> BoxliteResult<VmmMetrics> {
        use sysinfo::Pid;

        let pid = Pid::from_u32(self.pid);

        // Use the shared System instance for stateful CPU tracking
        let mut sys = self
            .metrics_sys
            .lock()
            .map_err(|e| BoxliteError::Internal(format!("metrics_sys lock poisoned: {}", e)))?;

        // Refresh process info - this updates the internal state for delta calculation
        sys.refresh_process(pid);

        // Try to get process information
        if let Some(proc_info) = sys.process(pid) {
            return Ok(VmmMetrics {
                cpu_percent: Some(proc_info.cpu_usage()),
                memory_bytes: Some(proc_info.memory()),
                disk_bytes: None, // Not available from process-level APIs
            });
        }

        // Process not found or not running - return empty metrics
        Ok(VmmMetrics::default())
    }

    fn is_running(&self) -> bool {
        crate::util::is_process_alive(self.pid)
    }
}

/// Emit the post-spawn TRACE event with the serialized `InstanceSpec`'s
/// secrets stripped out.
///
/// The serialized `InstanceSpec` (`config_json`) carries
/// `NetworkBackendConfig.secrets` (user-provided secret values) and, when a
/// MITM proxy is configured, `ca_key_pem` — the PKCS8 CA private key. The
/// config is deliberately piped via stdin rather than CLI args so those bytes
/// stay out of `/proc/<pid>/cmdline` (see `spawn.rs:97-99`); serializing them
/// into a TRACE log would defeat that mitigation.
///
/// This helper is the single audited site for that trace event so that
/// `redacted_box_config_trace_does_not_emit_config_json` can pin the
/// behavior with a real subscriber capture rather than relying on
/// source-grep heuristics.
fn emit_redacted_box_config_trace(engine: VmmKind, box_id: &str, config_json: &str) {
    tracing::trace!(
        engine = ?engine,
        box_id = %box_id,
        json_bytes = config_json.len(),
        "Box configuration prepared (raw config not logged; contains secrets)"
    );
}

// ============================================================================
// SHIM CONTROLLER - Spawning operations
// ============================================================================

/// Controller for spawning VM subprocesses.
///
/// Spawns the `boxlite-shim` binary in a subprocess and returns a ShimHandler
/// for runtime operations. The subprocess isolation ensures that VM process
/// takeover doesn't affect the host application.
pub struct ShimController {
    binary_path: PathBuf,
    engine_type: VmmKind,
    box_id: BoxID,
    /// Box options (includes security and volumes for jailer isolation)
    options: crate::runtime::options::BoxOptions,
    /// Box filesystem layout (provides paths for stderr, sockets, etc.)
    layout: BoxFilesystemLayout,
}

impl ShimController {
    /// Create a new ShimController.
    ///
    /// # Arguments
    /// * `binary_path` - Path to the boxlite-shim binary
    /// * `engine_type` - Type of VM engine to use (libkrun, firecracker, etc.)
    /// * `box_id` - Unique identifier for this box
    /// * `options` - Box options (includes security and volumes)
    /// * `layout` - Box filesystem layout
    ///
    /// # Returns
    /// * `Ok(ShimController)` - Successfully created controller
    /// * `Err(...)` - Failed to create controller (e.g., binary not found)
    pub fn new(
        binary_path: PathBuf,
        engine_type: VmmKind,
        box_id: BoxID,
        options: crate::runtime::options::BoxOptions,
        layout: BoxFilesystemLayout,
    ) -> BoxliteResult<Self> {
        // Verify that the shim binary exists
        if !binary_path.exists() {
            return Err(BoxliteError::Engine(format!(
                "Box runner binary not found: {}",
                binary_path.display()
            )));
        }

        Ok(Self {
            binary_path,
            engine_type,
            box_id,
            options,
            layout,
        })
    }
}

#[async_trait::async_trait]
impl VmmController for ShimController {
    async fn start(&mut self, config: &InstanceSpec) -> BoxliteResult<Box<dyn VmmHandlerTrait>> {
        tracing::debug!(
            "Preparing config: entrypoint.executable={}, entrypoint.args={:?}",
            config.guest_entrypoint.executable,
            config.guest_entrypoint.args
        );

        // Prepare environment with RUST_LOG if present
        // Note: We clone the config components needed for subprocess serialization
        let mut env = config.guest_entrypoint.env.clone();
        if let Ok(rust_log) = std::env::var("RUST_LOG") {
            env.push(("RUST_LOG".to_string(), rust_log.clone()));
        }

        // Create a temporary struct for serialization with modified env
        // This avoids cloning the config which now contains non-clonable NetworkBackend
        let mut guest_entrypoint = config.guest_entrypoint.clone();
        guest_entrypoint.env = env; // Use the modified env with RUST_LOG

        let serializable_config = InstanceSpec {
            engine: self.engine_type,
            // Box identification and security (from ShimController)
            box_id: self.box_id.to_string(),
            security: self.options.advanced.security.clone(),
            nested_virtualization: config.nested_virtualization,
            // VM configuration
            cpus: config.cpus,
            memory_mib: config.memory_mib,
            kernel: config.kernel.clone(),
            fs_shares: config.fs_shares.clone(),
            block_devices: config.block_devices.clone(),
            guest_entrypoint,
            transport: config.transport.clone(),
            ready_transport: config.ready_transport.clone(),
            guest_rootfs: config.guest_rootfs.clone(),
            network_backend_spec: config.network_backend_spec.clone(), // provisioning spec passed to the shim (stands up gvproxy)
            network_backend_endpoint: None, // Will be populated by shim (not serialized)
            disable_network: config.disable_network,
            home_dir: config.home_dir.clone(),
            console_output: config.console_output.clone(),
            exit_file: config.exit_file.clone(),
            detach: config.detach,
        };

        // Serialize the config for passing to subprocess
        let config_json = serde_json::to_string(&serializable_config)
            .map_err(|e| BoxliteError::Engine(format!("Failed to serialize config: {}", e)))?;

        // Clean up stale socket file if it exists (defense in depth)
        // Only relevant for Unix sockets
        if let boxlite_shared::BoxTransport::Unix { socket_path } = &config.transport
            && socket_path.exists()
        {
            tracing::warn!("Removing stale Unix socket: {}", socket_path.display());
            let _ = std::fs::remove_file(socket_path);
        }

        // Spawn Box subprocess with piped stdio
        tracing::info!(
            engine = ?self.engine_type,
            transport = ?config.transport,
            "Starting Box subprocess"
        );
        tracing::debug!(binary = %self.binary_path.display(), "Box runner binary");
        emit_redacted_box_config_trace(self.engine_type, self.box_id.as_str(), &config_json);

        // Measure subprocess spawn time
        let shim_spawn_start = Instant::now();
        let spawner = ShimSpawner::new(
            &self.binary_path,
            &self.layout,
            self.box_id.as_str(),
            &self.options,
        )
        .with_nested_virtualization(config.nested_virtualization);
        let spawned = spawner.spawn(&config_json, config.detach)?;
        // spawn_duration: time to create Box subprocess
        let shim_spawn_duration = shim_spawn_start.elapsed();

        let pid = spawned.child.id();
        tracing::info!(
            box_id = %self.box_id,
            pid = pid,
            shim_spawn_duration_ms = shim_spawn_duration.as_millis(),
            "boxlite-shim subprocess spawned"
        );

        // Note: We don't wait for guest readiness here anymore.
        // GuestConnectTask handles waiting for guest readiness,
        // which allows reusing that task across spawn/restart/reconnect.

        // Create handler from spawned shim (takes ownership of child + keepalive)
        let handler = ShimHandler::from_spawned(spawned, self.box_id.clone());

        tracing::info!(
            box_id = %self.box_id,
            "VM subprocess started successfully"
        );

        // The handler owns the Child from here: stop() waits it, and a handler
        // dropped without stop() hands it to a reaper thread (see its Drop).
        Ok(Box::new(handler))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Captures `tracing` output into a shared byte buffer so a test can
    /// assert what was (and wasn't) written by an event emitted within
    /// `tracing::subscriber::with_default`.
    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The kernel's view of `pid`: its `/proc/<pid>/stat` state letter, or
    /// `None` once the pid is gone. A zombie still has a `/proc` entry — state
    /// `Z` — so "gone" means somebody reaped it, which is what these tests
    /// are about.
    #[cfg(target_os = "linux")]
    fn proc_state(pid: u32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `pid (comm) S ...` — comm may contain spaces and parens, so take
        // the state after the LAST `)`.
        stat.rsplit_once(')')?.1.trim_start().chars().next()
    }

    #[cfg(target_os = "linux")]
    fn handler_for(child: std::process::Child) -> ShimHandler {
        ShimHandler::from_spawned(
            SpawnedShim {
                child,
                keepalive: None,
            },
            BoxID::parse("reaptestbox1").expect("valid box id"),
        )
    }

    /// Poll until `pid` leaves the process table, or give up at `deadline`.
    #[cfg(target_os = "linux")]
    fn gone_within(pid: u32, deadline: std::time::Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if proc_state(pid).is_none() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    /// The #140 leak: a handler dropped without `stop()` — the normal fate of
    /// a detached box's handler once its short-lived runtime goes away — must
    /// still get its launcher reaped when that launcher exits later, from a
    /// kill this process had no part in. Without the Drop impl the pid sits
    /// in state `Z` indefinitely, and this test fails on the deadline.
    ///
    /// Revert procedure: delete `impl Drop for ShimHandler`. The pid then
    /// stays `Z` and the assertion fires.
    #[cfg(target_os = "linux")]
    #[test]
    fn dropped_handler_reaps_its_launcher_after_it_exits() {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        drop(handler_for(child));
        // Still running: the drop must not have killed or blocked on it.
        assert!(
            matches!(proc_state(pid), Some(s) if s != 'Z'),
            "dropping the handler must leave a live launcher alone"
        );

        // The box is stopped from elsewhere — another process's `stop()`.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };

        let reaped = gone_within(pid, std::time::Duration::from_secs(5));
        if !reaped {
            // Do not leak the zombie into the rest of the test binary.
            unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), 0) };
        }
        assert!(
            reaped,
            "a dropped handler's launcher stayed <defunct> after it exited \
             (state {:?}) — nothing waited it",
            proc_state(pid)
        );
    }

    /// A launcher that has already exited when its handler drops is reaped on
    /// the spot, without a thread.
    #[cfg(target_os = "linux")]
    #[test]
    fn dropped_handler_reaps_an_already_exited_launcher() {
        let child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        // Let it exit and become a zombie before the drop.
        let start = Instant::now();
        while proc_state(pid) != Some('Z') && start.elapsed().as_secs() < 5 {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(proc_state(pid), Some('Z'), "precondition: a zombie");

        drop(handler_for(child));
        assert_eq!(
            proc_state(pid),
            None,
            "dropping the handler must reap a launcher that already exited"
        );
    }

    /// `stop()` still owns the wait. Afterwards the Drop impl has nothing
    /// left to do, so it must not start a second waiter on a pid that may
    /// already be reused.
    #[cfg(target_os = "linux")]
    #[test]
    fn stop_waits_the_launcher_itself_and_leaves_drop_nothing() {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let mut handler = handler_for(child);
        // The graceful half is what matters here; the cgroup sweep
        // `stop()` also runs is best-effort and finds no such box.
        handler.graceful_stop().expect("graceful stop");
        assert_eq!(proc_state(pid), None, "stop() must reap the launcher");
        assert!(handler.process.is_none(), "stop() must consume the Child");
        drop(handler);
    }

    /// Behavioral regression for the leak fixed in this commit: feed a
    /// `config_json` whose body contains sentinel CA-key / secret bytes
    /// into the helper that is the *only* site allowed to emit the
    /// post-spawn TRACE event, capture every byte the subscriber writes,
    /// and assert the sentinels never appear — while the redacted fields
    /// (`box_id`, `json_bytes`) do. If any future change reintroduces
    /// `config = %config_json` (or any other form that lets the raw bytes
    /// reach the subscriber), the sentinel assertion fires.
    #[test]
    fn redacted_box_config_trace_does_not_emit_config_json() {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(BufWriter(buf.clone()))
            .with_ansi(false)
            .finish();

        let key_sentinel = "PKCS8_PRIVATE_KEY_SENTINEL_DO_NOT_LEAK";
        let secret_sentinel = "USER_SECRET_VALUE_SENTINEL_DO_NOT_LEAK";
        let config_json = format!(
            r#"{{"secrets":[{{"name":"db","value":"{}"}}],"ca_key_pem":"-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----"}}"#,
            secret_sentinel, key_sentinel
        );
        let expected_len = config_json.len();

        tracing::subscriber::with_default(subscriber, || {
            emit_redacted_box_config_trace(VmmKind::Libkrun, "test-box-id", &config_json);
        });

        let output = String::from_utf8(buf.lock().unwrap().clone()).expect("utf8 trace output");

        assert!(
            !output.contains(key_sentinel),
            "CA private key sentinel leaked into trace output: {output}"
        );
        assert!(
            !output.contains(secret_sentinel),
            "user secret sentinel leaked into trace output: {output}"
        );
        assert!(
            output.contains("test-box-id"),
            "box_id (non-sensitive) should appear in trace output: {output}"
        );
        assert!(
            output.contains(&format!("json_bytes={expected_len}")),
            "json_bytes redacted summary should appear: {output}"
        );
    }

    /// Workspace-wide regression: the behavioral test above pins the helper
    /// itself. It does **not** pin the invariant that the helper is the
    /// *only* site emitting `config_json` to a `tracing::*` macro — a new
    /// `tracing::trace!(config = %config_json, ...)` added anywhere else in
    /// the workspace (this crate, the shim binary which reads the same
    /// JSON from stdin, etc.) would slip past it.
    ///
    /// `tracing`'s `%` (Display) and `?` (Debug) field-value sigils are
    /// unambiguous markers for "this expression's formatted output goes
    /// into the event". Forbid both `%config_json` and `?config_json`
    /// anywhere in production source under the workspace's `src/`. Test
    /// code (anything past the first `#[cfg(test)]` in each file) is
    /// exempt so this patrol can talk about the patterns it catches
    /// without tripping over itself.
    #[test]
    fn no_config_json_in_tracing_sigil_workspace_wide() {
        fn walk_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk_rs(&p, out);
                } else if p.extension().is_some_and(|e| e == "rs") {
                    out.push(p);
                }
            }
        }

        // CARGO_MANIFEST_DIR points at this crate (src/boxlite); the
        // workspace root is two levels up, and the workspace-level source
        // tree (which also includes src/shim, src/cli, …) lives at
        // <workspace-root>/src.
        let workspace_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("src");
        let mut files = Vec::new();
        walk_rs(&workspace_src, &mut files);
        assert!(
            !files.is_empty(),
            "patrol found zero .rs files under {}",
            workspace_src.display()
        );

        let forbidden = ["%config_json", "?config_json"];
        let mut offenders = Vec::new();
        for path in &files {
            let src = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Strip every `#[cfg(test)]` block (only the first one is
            // sufficient because tests sit at the bottom of a file by
            // convention; if a project ever puts a `#[cfg(test)]` in the
            // middle, the patrol still gates everything above the first
            // such marker).
            let production = match src.find("#[cfg(test)]") {
                Some(idx) => &src[..idx],
                None => &src,
            };
            for needle in &forbidden {
                if production.contains(needle) {
                    offenders.push(format!("{}: contains {needle:?}", path.display()));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "`config_json` reached a `tracing::*` field sigil in production code — \
             that string carries secrets and a PKCS8 CA private key. Route the \
             log through `emit_redacted_box_config_trace` instead.\n  {}",
            offenders.join("\n  ")
        );
    }
}
