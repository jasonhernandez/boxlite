//! Process validation utilities for PID checking and verification.

use std::time::Duration;

// ============================================================================
// PROCESS MONITOR - Wait for process exit with exit code capture
// ============================================================================

/// Exit status from process monitoring.
///
/// Distinguishes between cases where we can capture the exit code vs. cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExit {
    /// Process exited, we captured the exit code.
    ///
    /// This happens when we're the parent process (spawned the child)
    /// and `waitpid()` successfully reaped the process.
    Code(i32),

    /// Process is dead but exit code is unavailable.
    ///
    /// This happens in "attached" mode when we reconnect to an existing
    /// process. Unix only allows the parent to `waitpid()` its children,
    /// so we get `ECHILD` and fall back to `kill(pid, 0)` to detect death.
    Unknown,
}

/// Monitors a process for exit, handling both owned and attached cases.
///
/// # Unix Parent/Child Constraint
///
/// Only the parent process can `waitpid()` on a child. When we "attach"
/// to an existing process (e.g., reconnect after detach), we're not the
/// parent, so `waitpid()` returns `ECHILD`. In that case, we fall back
/// to `kill(pid, 0)` to detect process death, but cannot get the exit code.
///
/// # Example
///
/// ```ignore
/// let monitor = ProcessMonitor::new(pid);
///
/// // Non-blocking check
/// if let Some(exit) = monitor.try_wait() {
///     match exit {
///         ProcessExit::Code(code) => println!("Exited with code {}", code),
///         ProcessExit::Unknown => println!("Process died, code unknown"),
///     }
/// }
///
/// // Async wait until exit
/// let exit = monitor.wait_for_exit().await;
/// ```
pub struct ProcessMonitor {
    pid: u32,
    /// A pidfd for the process, opened when the monitor is built. It names
    /// that one process, not whatever later holds the same pid number.
    ///
    /// A bare pid is not a stable identity once somebody else may reap the
    /// process: the shim launcher's own reaper thread (see
    /// `ShimHandler`'s Drop) waits it the moment it exits, and the kernel may
    /// then hand the number to an unrelated process. A monitor that only had
    /// the number would see that stranger through `kill(pid, 0)` and report
    /// the box running forever. Through the pidfd it sees the exit instead,
    /// and `waitid(P_PIDFD)` can only ever reap the process it names.
    ///
    /// `None` when `pidfd_open` is unavailable (not Linux, a kernel before
    /// 5.3, or the pid is already gone): then the monitor falls back to the
    /// bare pid, as before.
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::OwnedFd>,
}

/// `idtype_t` for `waitid` on a pidfd (Linux 5.4). Not exported by `libc`.
#[cfg(target_os = "linux")]
const P_PIDFD: libc::idtype_t = 3;

#[cfg(target_os = "linux")]
fn pidfd_open(pid: u32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: pidfd_open returned a fresh descriptor that we now own.
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

/// Has the process behind `pidfd` exited? A pidfd polls readable once it
/// has, whether or not it has been reaped since — so this stays true even
/// after the pid number has been reused.
#[cfg(target_os = "linux")]
fn pidfd_exited(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    let mut pfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    n > 0 && (pfd.revents & libc::POLLIN) != 0
}

impl ProcessMonitor {
    /// Create a new process monitor for the given PID.
    ///
    /// Build it while `pid` still names the process you mean — before it can
    /// have been reaped — so the pidfd pins that process.
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            #[cfg(target_os = "linux")]
            pidfd: pidfd_open(pid),
        }
    }

    /// Get the monitored process ID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Check if the process is still alive.
    pub fn is_alive(&self) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.pidfd {
            return !pidfd_exited(fd);
        }
        is_process_alive(self.pid)
    }

    /// Send `sig` to the monitored process — through the pidfd when there is
    /// one, so it can only ever reach that process and never a later holder of
    /// the same pid number. Best-effort: an already-exited process is fine.
    pub fn signal(&self, sig: i32) {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.pidfd {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                );
            }
            return;
        }
        unsafe {
            libc::kill(self.pid as i32, sig);
        }
    }

    /// Try to reap the process and get exit code (non-blocking).
    ///
    /// # Returns
    ///
    /// - `Some(ProcessExit::Code(n))` - Process exited, we got the code
    /// - `Some(ProcessExit::Unknown)` - Process dead, but we're not parent
    ///   (ECHILD), or somebody else already reaped it
    /// - `None` - Process still running
    pub fn try_wait(&self) -> Option<ProcessExit> {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.pidfd {
            return Self::try_wait_pidfd(fd);
        }

        let mut status: i32 = 0;
        let result = unsafe { libc::waitpid(self.pid as i32, &mut status, libc::WNOHANG) };

        if result > 0 {
            // We reaped it, decode the status
            Some(ProcessExit::Code(decode_wait_status(status)))
        } else if result < 0 && !self.is_alive() {
            // ECHILD (not our child) but process is dead
            Some(ProcessExit::Unknown)
        } else {
            // Still running (result == 0) or error but still alive
            None
        }
    }

    /// `try_wait` through the pidfd: reap only the process it names, and
    /// judge liveness by it rather than by the pid number.
    #[cfg(target_os = "linux")]
    fn try_wait_pidfd(fd: &std::os::fd::OwnedFd) -> Option<ProcessExit> {
        use std::os::fd::AsRawFd;
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                P_PIDFD,
                fd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG,
            )
        };
        if r == 0 {
            // WNOHANG with nothing to report leaves si_pid zero.
            if unsafe { info.si_pid() } == 0 {
                return None;
            }
            let status = unsafe { info.si_status() };
            let code = match info.si_code {
                libc::CLD_EXITED => status,
                libc::CLD_KILLED | libc::CLD_DUMPED => 128 + status,
                _ => -1,
            };
            return Some(ProcessExit::Code(code));
        }
        // ECHILD: not our child, or already reaped by someone else (the
        // launcher's reaper thread). Either way the pidfd still knows
        // whether *this* process has exited.
        if pidfd_exited(fd) {
            Some(ProcessExit::Unknown)
        } else {
            None
        }
    }

    /// Async poll until the process exits.
    ///
    /// Polls every 500ms until the process terminates.
    pub async fn wait_for_exit(&self) -> ProcessExit {
        let poll_interval = Duration::from_millis(500);
        loop {
            if let Some(exit) = self.try_wait() {
                return exit;
            }
            tokio::time::sleep(poll_interval).await;
        }
    }
}

/// Decode waitpid status into exit code using Unix conventions.
///
/// - Normal exit: returns `WEXITSTATUS` (0-255)
/// - Signal termination: returns `128 + signal_number` (Unix convention)
/// - Other: returns -1
fn decode_wait_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status) // Unix convention
    } else {
        -1 // Unknown
    }
}

/// Kill a process with SIGKILL.
///
/// # Returns
/// * `true` - Process was killed or doesn't exist
/// * `false` - Failed to kill (permission denied)
pub fn kill_process(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, libc::SIGKILL) == 0 || !is_process_alive(pid) }
}

/// Read a foreign process's start-time fingerprint for PID-reuse detection.
///
/// Parent-side counterpart of [`crate::jailer::common::pid::write_pid_file_raw`],
/// which captures the same value in the child. Recovery compares the
/// value stored in `shim.pid` against this reading; a mismatch reliably
/// signals PID reuse.
///
/// # Units (platform-specific, never cross-compared)
/// * **Linux**: clock ticks since boot (field 22 of `/proc/PID/stat`).
/// * **macOS**: epoch microseconds (`pbi_start_tvsec * 1e6 + pbi_start_tvusec`).
///
/// # Returns
/// * `Some(t)` — start-time captured.
/// * `None` — process does not exist or platform read failed (treat as Mismatch).
pub fn process_start_time(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        process_start_time_linux(pid)
    }

    #[cfg(target_os = "macos")]
    {
        process_start_time_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "linux")]
fn process_start_time_linux(pid: u32) -> Option<u64> {
    // `/proc/PID/stat` format:  PID (COMM) STATE PPID ... STARTTIME(22) ...
    // COMM is the only parenthesized field — split on the last `)` to skip
    // past names containing spaces or close-parens.
    let raw = std::fs::read(format!("/proc/{}/stat", pid)).ok()?;
    let after_comm_pos = raw.iter().rposition(|&b| b == b')')?;
    let tail = &raw[after_comm_pos + 1..];
    // After the closing `)` and one space, fields are space-separated.
    // STARTTIME is field 22 of the full line; in `tail` it is field 20
    // (fields 1 and 2 — pid and comm — are already consumed).
    let tail_str = std::str::from_utf8(tail).ok()?;
    tail_str.split_whitespace().nth(19)?.parse::<u64>().ok()
}

#[cfg(target_os = "macos")]
fn process_start_time_macos(pid: u32) -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let expected_size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            expected_size,
        )
    };
    if bytes != expected_size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

/// Check if a process with the given PID exists.
///
/// Uses `libc::kill(pid, 0)` which sends a null signal to check existence.
/// A zombie/defunct process is treated as not alive.
///
/// # Returns
/// * `true` - Process exists
/// * `false` - Process does not exist or permission denied
pub fn is_process_alive(pid: u32) -> bool {
    if unsafe { libc::kill(pid as i32, 0) } != 0 {
        return false;
    }

    !is_process_zombie(pid)
}

fn is_process_zombie(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        is_process_zombie_linux(pid)
    }

    #[cfg(target_os = "macos")]
    {
        is_process_zombie_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn is_process_zombie_linux(pid: u32) -> bool {
    let status_path = format!("/proc/{pid}/status");
    let Ok(status) = std::fs::read_to_string(status_path) else {
        return false;
    };

    status.lines().find_map(|line| {
        line.strip_prefix("State:")
            .and_then(|state| state.trim_start().chars().next())
    }) == Some('Z')
}

#[cfg(target_os = "macos")]
fn is_process_zombie_macos(pid: u32) -> bool {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let expected_size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;

    let bytes = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            expected_size,
        )
    };

    if bytes != expected_size {
        if bytes != 0 {
            return false;
        }

        // On macOS, PROC_PIDTBSDINFO may return 0 for zombies.
        // Distinguish that from live processes by checking whether
        // the executable path is still queryable.
        let mut path_buf = [0 as libc::c_char; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let path_len = unsafe {
            libc::proc_pidpath(
                pid as i32,
                path_buf.as_mut_ptr().cast(),
                path_buf.len() as u32,
            )
        };

        return path_len == 0;
    }

    let info = unsafe { info.assume_init() };
    info.pbi_status == libc::SZOMB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_process_alive_current() {
        // Current process should always be alive
        let current_pid = std::process::id();
        assert!(is_process_alive(current_pid));
    }

    #[test]
    fn test_is_process_alive_invalid() {
        // Use very high PIDs unlikely to exist
        // Note: u32::MAX becomes -1 when cast to i32, which has special meaning in kill()
        // Note: PID 0 might exist on some systems (kernel/scheduler)
        assert!(!is_process_alive(999999999));
        assert!(!is_process_alive(888888888));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_is_process_alive_false_for_zombie() {
        use std::time::{Duration, Instant};

        struct PidReaper {
            pid: libc::pid_t,
        }

        impl Drop for PidReaper {
            fn drop(&mut self) {
                let mut status = 0;
                let _ = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            }
        }

        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "fork() failed");
        if child_pid == 0 {
            unsafe { libc::_exit(0) };
        }

        let _reaper = PidReaper { pid: child_pid };
        let child_pid = child_pid as u32;

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let raw_exists = unsafe { libc::kill(child_pid as i32, 0) == 0 };

            if !raw_exists {
                // Some environments auto-reap exited children immediately.
                // In that case there is no zombie window to assert against.
                return;
            }

            if !is_process_alive(child_pid) {
                return;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        panic!("Exited child remained reported as alive while still existing");
    }

    // ========================================================================
    // ProcessMonitor tests
    // ========================================================================

    #[test]
    fn test_decode_wait_status_normal_exit() {
        // Simulate WIFEXITED with exit code 0
        // On Unix, exit status is stored in bits 8-15
        let status = 0 << 8; // exit(0)
        assert_eq!(decode_wait_status(status), 0);

        let status = 1 << 8; // exit(1)
        assert_eq!(decode_wait_status(status), 1);

        let status = 42 << 8; // exit(42)
        assert_eq!(decode_wait_status(status), 42);
    }

    #[test]
    fn test_decode_wait_status_signal() {
        // Simulate WIFSIGNALED with signal
        // On Unix, signal is stored in bits 0-6, with bit 7 = core dump
        let sigterm = libc::SIGTERM; // 15
        assert_eq!(decode_wait_status(sigterm), 128 + sigterm);

        let sigkill = libc::SIGKILL; // 9
        assert_eq!(decode_wait_status(sigkill), 128 + sigkill);

        let sigabrt = libc::SIGABRT; // 6
        assert_eq!(decode_wait_status(sigabrt), 128 + sigabrt);
    }

    #[test]
    fn test_process_monitor_current_process() {
        let monitor = ProcessMonitor::new(std::process::id());

        // Current process is alive
        assert!(monitor.is_alive());

        // try_wait should return None (still running)
        assert!(monitor.try_wait().is_none());
    }

    #[test]
    fn test_process_monitor_invalid_pid() {
        let monitor = ProcessMonitor::new(999999999);

        // Invalid PID is not alive
        assert!(!monitor.is_alive());

        // try_wait should return Unknown (not our child, but dead)
        assert_eq!(monitor.try_wait(), Some(ProcessExit::Unknown));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    #[allow(clippy::zombie_processes)] // ProcessMonitor::try_wait() calls waitpid() internally
    fn test_process_monitor_child_exit() {
        use std::process::Command;

        // Spawn a child process that exits immediately with code 42
        let child = Command::new("sh")
            .arg("-c")
            .arg("exit 42")
            .spawn()
            .expect("Failed to spawn child");

        let monitor = ProcessMonitor::new(child.id());

        // Wait for the child to exit (blocking in test is OK)
        std::thread::sleep(std::time::Duration::from_millis(100));

        // ProcessMonitor::try_wait() calls waitpid() which reaps the child
        match monitor.try_wait() {
            Some(ProcessExit::Code(code)) => assert_eq!(code, 42),
            other => panic!("Expected ProcessExit::Code(42), got {:?}", other),
        }
    }

    /// The #140 review case: the launcher is reaped by somebody else (the
    /// shim handler's reaper thread) and its pid number is reused before the
    /// watcher's next poll. The monitor must report the exit, not the
    /// stranger now holding the number.
    ///
    /// Real pid reuse cannot be forced here, so the stranger is simulated:
    /// the monitor's pid number is pointed at a process that is certainly
    /// alive (this test process) while its pidfd pins the dead child. A
    /// monitor that trusted the bare pid would say "running"; this one must
    /// say "exited".
    #[cfg(target_os = "linux")]
    #[test]
    fn process_monitor_sees_exit_through_the_pidfd_after_pid_reuse() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let monitor = ProcessMonitor {
            pid: std::process::id(), // the "reused" number: alive
            pidfd: pidfd_open(child.id()),
        };
        assert!(monitor.pidfd.is_some(), "pidfd_open unsupported here");
        // Someone else reaps it, as the reaper thread would.
        child.wait().expect("wait");

        assert!(
            is_process_alive(monitor.pid),
            "precondition: the bare pid number names a live process"
        );
        assert_eq!(monitor.try_wait(), Some(ProcessExit::Unknown));
        assert!(!monitor.is_alive());
    }

    /// And the reaper-first race without reuse: the monitor's own
    /// `waitid(P_PIDFD)` gets ECHILD and still reports the exit.
    #[cfg(target_os = "linux")]
    #[test]
    fn process_monitor_reports_exit_when_someone_else_reaped_it() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let monitor = ProcessMonitor::new(child.id());
        child.wait().expect("wait");
        assert_eq!(monitor.try_wait(), Some(ProcessExit::Unknown));
    }

    /// While alive, the pidfd path reports running and reaps nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn process_monitor_pidfd_reports_running_child_as_running() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let monitor = ProcessMonitor::new(child.id());
        assert!(monitor.try_wait().is_none());
        assert!(monitor.is_alive());
        child.kill().ok();
        child.wait().ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::zombie_processes)] // try_wait reaps it through the pidfd
    fn process_monitor_pidfd_reports_signal_exit_code() {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let monitor = ProcessMonitor::new(child.id());
        unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        let start = std::time::Instant::now();
        let exit = loop {
            if let Some(e) = monitor.try_wait() {
                break e;
            }
            assert!(start.elapsed().as_secs() < 5, "no exit seen");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(exit, ProcessExit::Code(128 + libc::SIGKILL));
    }

    #[test]
    fn test_process_exit_equality() {
        assert_eq!(ProcessExit::Code(0), ProcessExit::Code(0));
        assert_eq!(ProcessExit::Code(1), ProcessExit::Code(1));
        assert_eq!(ProcessExit::Unknown, ProcessExit::Unknown);

        assert_ne!(ProcessExit::Code(0), ProcessExit::Code(1));
        assert_ne!(ProcessExit::Code(0), ProcessExit::Unknown);
    }
}
