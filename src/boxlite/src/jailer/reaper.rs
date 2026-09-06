//! Process-tree reaping for a box's sandbox.
//!
//! The mechanism behind [`super::reap_box`]'s guarantee that a stopped box
//! leaves no live process behind.
//!
//! # Why the recorded pid is not enough
//!
//! `state.pid` is the *outer* launcher — on Linux the first `bwrap`. A
//! detached box's inner pid namespace (inner `bwrap` + `boxlite-shim` + the
//! VM) is not tied to that launcher's lifetime, so signalling the recorded pid
//! reparents the inner tree to init instead of ending it, and the guest's
//! memory stays resident. Killing the launcher also *destroys* the evidence:
//! once the children are reparented, no ppid walk can still associate them
//! with the box.
//!
//! # Why the cgroup is not enough either
//!
//! [`super::cgroup::kill_cgroup`] reaps the whole tree in one write and is the
//! preferred path, but it is best-effort by construction: it needs cgroup v2,
//! kernel ≥ 5.14 for `cgroup.kill`, and — rootless — a delegated
//! `user@{uid}.service` subtree that a process started from an ssh session
//! scope may not have. When any of that is missing the write fails silently
//! and the box's processes survive.
//!
//! # What this module does instead
//!
//! It identifies a box's processes the way an operator does: by the box's own
//! runtime directory in their argv. Every process of a box carries
//! `…/boxes/{box_id}/…` in its command line — the sandbox mount arguments, the
//! copied shim's absolute path, or both. That identification survives
//! reparenting, needs no bookkeeping, and cannot be confused by pid reuse: a
//! recycled pid belongs to an unrelated program with an unrelated argv.

use crate::runtime::id::BoxID;
use crate::util::{is_process_alive, kill_process};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// How long a box's processes get to exit after `SIGTERM` before `SIGKILL`.
///
/// Matches the shim's own graceful-shutdown budget: by the time this module
/// runs, the recorded pid has already had that long to bring the VM down
/// cleanly, so anything still here is a survivor, not a slow flusher.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// How long to wait for the kernel to tear down a `SIGKILL`ed process before
/// declaring it a survivor. Only bounds the failure path.
const KILL_SETTLE: Duration = Duration::from_secs(1);

/// Poll interval while waiting for processes to exit.
const POLL: Duration = Duration::from_millis(50);

/// Live pids whose command line references box `box_id`'s runtime directory.
///
/// Three exclusions keep the sweep from reaching anything that is not the
/// box's own sandbox:
///
/// * **The caller and its ancestors.** A caller invoked as
///   `boxlite rm -f {box_id}` has the id in its own argv, and the sweep must
///   not be able to end the very process performing it. The needle carries
///   both slashes (`boxes/{id}/`) so such a command line does not match in the
///   first place; excluding the lineage is the belt to that suspenders.
/// * **Threads.** `sysinfo` reports a thread under its own tid; signalling one
///   signals its whole thread group, so listing them only duplicates work.
/// * **Other users' processes.** A shared host may run another user's boxes
///   under the same path shape; a reap must never reach across that line.
pub(crate) fn box_processes(box_id: &BoxID) -> Vec<u32> {
    let needle = format!("boxes/{}/", box_id.as_str());

    // `everything()` rather than the default refresh: `refresh_processes()`
    // leaves `cmd()` empty on Linux, which would silently match nothing.
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::everything());

    let self_pid = sysinfo::Pid::from_u32(std::process::id());
    let lineage = lineage_of(&sys, self_pid);
    let self_uid = sys.process(self_pid).and_then(|p| p.user_id()).cloned();

    let mut pids: Vec<u32> = sys
        .processes()
        .iter()
        .filter(|(pid, _)| !lineage.contains(&pid.as_u32()))
        .filter(|(_, proc_)| proc_.thread_kind().is_none())
        .filter(|(_, proc_)| self_uid.is_none() || proc_.user_id() == self_uid.as_ref())
        .filter(|(_, proc_)| proc_.cmd().iter().any(|arg| arg.contains(&needle)))
        .map(|(pid, _)| pid.as_u32())
        .filter(|pid| is_process_alive(*pid))
        .collect();

    pids.sort_unstable();
    pids
}

/// Terminate every process still belonging to box `box_id`.
///
/// `SIGTERM`, bounded wait, `SIGKILL`, bounded wait. Returns the pids that
/// outlived `SIGKILL` — an empty vector means the box owns no process on this
/// host any more, which is the only outcome a caller may report as success.
///
/// Idempotent and cheap when there is nothing to do: a box with no live
/// process costs one `/proc` scan and returns immediately.
pub(crate) fn reap_box_processes(box_id: &BoxID) -> Vec<u32> {
    let pids = box_processes(box_id);
    if pids.is_empty() {
        return Vec::new();
    }

    tracing::debug!(
        box_id = %box_id,
        pids = ?pids,
        "Reaping sandbox processes that outlived the recorded pid"
    );

    for pid in &pids {
        // SAFETY: `kill` with a positive pid is a plain syscall; a pid that
        // has already exited yields ESRCH, which is the intended no-op.
        unsafe { libc::kill(*pid as i32, libc::SIGTERM) };
    }

    if let Some(alive) = wait_for_exit(&pids, TERM_GRACE) {
        for pid in &alive {
            tracing::warn!(box_id = %box_id, pid, "Sandbox process ignored SIGTERM, killing");
            kill_process(*pid);
        }
        if let Some(survivors) = wait_for_exit(&alive, KILL_SETTLE) {
            return survivors;
        }
    }

    Vec::new()
}

/// Poll until every pid is gone or `budget` elapses.
///
/// Returns `None` once all are gone, or `Some(still_alive)` on timeout.
fn wait_for_exit(pids: &[u32], budget: Duration) -> Option<Vec<u32>> {
    let deadline = Instant::now() + budget;
    loop {
        let alive: Vec<u32> = pids
            .iter()
            .copied()
            .filter(|pid| is_process_alive(*pid))
            .collect();
        if alive.is_empty() {
            return None;
        }
        if Instant::now() >= deadline {
            return Some(alive);
        }
        std::thread::sleep(POLL);
    }
}

/// `start` and every ancestor of it, from one process snapshot.
fn lineage_of(sys: &sysinfo::System, start: sysinfo::Pid) -> HashSet<u32> {
    let mut lineage = HashSet::new();
    let mut cursor = Some(start);
    while let Some(pid) = cursor {
        if !lineage.insert(pid.as_u32()) {
            break; // defensive: a cycle would otherwise spin forever
        }
        cursor = sys.process(pid).and_then(|p| p.parent());
    }
    lineage
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    /// A shell that idles under the argv `/…/boxes/<id>/bin/boxlite-shim`, so
    /// it is attributed to the box exactly as a real sandbox process is.
    ///
    /// The path is passed as `sh -c <script> <argv0>` rather than written to
    /// disk and executed: nothing has to exist on the filesystem, and there is
    /// no `ETXTBSY` race against a sibling test still holding a write fd.
    struct FakeSandboxProcess {
        child: Child,
    }

    impl FakeSandboxProcess {
        fn spawn(box_id: &str, trap_term: bool) -> Self {
            let script = if trap_term {
                "trap '' TERM; while :; do sleep 1; done"
            } else {
                "while :; do sleep 1; done"
            };
            let child = Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .arg(format!("/nonexistent/boxes/{box_id}/bin/boxlite-shim"))
                .spawn()
                .unwrap();
            // Give the kernel a moment to publish the new argv in /proc.
            std::thread::sleep(Duration::from_millis(200));
            Self { child }
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }
    }

    impl Drop for FakeSandboxProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn box_id(s: &str) -> BoxID {
        BoxID::parse(s).expect("valid test box id")
    }

    #[test]
    fn finds_a_process_holding_the_box_directory() {
        let id = box_id("reaperFindMe");
        let proc_ = FakeSandboxProcess::spawn(id.as_str(), false);

        assert!(
            box_processes(&id).contains(&proc_.pid()),
            "a process whose argv carries boxes/{}/ must be attributed to the box",
            id.as_str()
        );
    }

    #[test]
    fn ignores_processes_of_another_box() {
        let mine = box_id("reaperMineAA");
        let theirs = box_id("reaperTheirs");
        let proc_ = FakeSandboxProcess::spawn(theirs.as_str(), false);

        assert!(
            !box_processes(&mine).contains(&proc_.pid()),
            "the sweep must be scoped to one box's directory"
        );
    }

    #[test]
    fn never_attributes_the_caller_or_its_ancestors_to_a_box() {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::everything());
        let self_pid = sysinfo::Pid::from_u32(std::process::id());
        let lineage = lineage_of(&sys, self_pid);

        assert!(
            lineage.contains(&std::process::id()),
            "the calling process must always be excluded"
        );
        assert!(
            lineage.len() > 1,
            "the caller's ancestors must be excluded too"
        );
        // Reaping cannot end the caller even if its own argv matched.
        let id = box_id("reaperSelfXX");
        assert!(!box_processes(&id).contains(&std::process::id()));
    }

    #[test]
    fn reaping_a_box_with_no_processes_is_a_noop() {
        let id = box_id("reaperEmptyA");
        assert!(reap_box_processes(&id).is_empty());
    }

    #[test]
    fn reaps_a_process_holding_the_box_directory() {
        let id = box_id("reaperTermAA");
        let proc_ = FakeSandboxProcess::spawn(id.as_str(), false);
        let pid = proc_.pid();

        assert!(
            reap_box_processes(&id).is_empty(),
            "reap must report success"
        );
        assert!(!is_process_alive(pid), "the box's process must be gone");
    }

    #[test]
    fn escalates_to_sigkill_when_sigterm_is_ignored() {
        let id = box_id("reaperKillAA");
        let proc_ = FakeSandboxProcess::spawn(id.as_str(), true);
        let pid = proc_.pid();

        assert!(
            reap_box_processes(&id).is_empty(),
            "a process that ignores SIGTERM must still be reaped"
        );
        assert!(!is_process_alive(pid), "the box's process must be gone");
    }
}
