//! Filesystem utilities for the jailer module.
//!
//! Cross-platform file operations used by the jailer.

use std::fs;
use std::io;
use std::path::Path;

/// Copy a file if the source is newer or sizes differ.
///
/// This implements a simple "copy-if-newer" pattern to avoid unnecessary
/// file copies when the destination already has an up-to-date version.
///
/// # Arguments
///
/// * `src` - Source file path
/// * `dest` - Destination file path
///
/// The destination always ends up with the source's mode, so a copied
/// executable stays executable. See [`copy_permissions`] for why that needs
/// saying.
///
/// # Returns
///
/// * `Ok(true)` - File was copied
/// * `Ok(false)` - File was skipped (destination is up-to-date)
/// * `Err(e)` - Copy failed
///
/// # Example
///
/// ```ignore
/// use boxlite::jailer::common::fs::copy_if_newer;
///
/// let copied = copy_if_newer("/path/to/src", "/path/to/dest")?;
/// if copied {
///     println!("File was copied");
/// } else {
///     println!("File was already up-to-date");
/// }
/// ```
#[allow(dead_code)] // Utility function for future DRY refactoring
pub fn copy_if_newer(src: &Path, dest: &Path) -> io::Result<bool> {
    let should_copy = should_copy_file(src, dest);

    if should_copy {
        // Try reflink (CoW clone) first — instant on APFS/btrfs/xfs.
        // Reflink creates a new inode (unlike hardlink), so each box gets
        // independent page cache entries and .text sections in memory.
        if reflink_copy::reflink(src, dest).is_err() {
            // Fallback to regular copy (ext4, tmpfs, etc.)
            fs::copy(src, dest)?;
        }
        copy_permissions(src, dest)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Give `dest` the same mode as `src`.
///
/// `fs::copy` does this already, `reflink` does not: it creates the
/// destination with the process default (`0666 & ~umask`), so the executable
/// bit is dropped. Which of the two ran depends on the filesystem, so the same
/// copy produced a `0755` shim on one host and a `0664` one on another — and
/// the `0664` one made every box on it fail to start with
/// `bwrap: execvp …/bin/boxlite-shim: Permission denied`, reported as "The VM
/// failed to start" with nothing pointing at a mode.
///
/// Setting the mode explicitly makes the result independent of which path was
/// taken, and of the filesystem underneath.
#[cfg(unix)]
fn copy_permissions(src: &Path, dest: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(src)?.permissions().mode() & 0o7777;
    fs::set_permissions(dest, fs::Permissions::from_mode(mode))
}

/// See the Unix variant.
#[cfg(not(unix))]
fn copy_permissions(src: &Path, dest: &Path) -> io::Result<()> {
    let perms = fs::metadata(src)?.permissions();
    fs::set_permissions(dest, perms)
}

/// Check if a file should be copied based on modification time and size.
///
/// Returns `true` if:
/// - Destination doesn't exist
/// - Source is newer than destination
/// - Source and destination have different sizes
#[allow(dead_code)] // Used by copy_if_newer
fn should_copy_file(src: &Path, dest: &Path) -> bool {
    if !dest.exists() {
        return true;
    }

    let src_meta = fs::metadata(src).ok();
    let dst_meta = fs::metadata(dest).ok();

    match (src_meta, dst_meta) {
        (Some(src), Some(dst)) => {
            // Copy if source is newer or sizes differ
            src.modified().ok() > dst.modified().ok() || src.len() != dst.len()
        }
        // If we can't read metadata, copy to be safe
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_copy_if_newer_new_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dest.txt");

        fs::write(&src, "hello").unwrap();

        let copied = copy_if_newer(&src, &dest).unwrap();
        assert!(copied, "Should copy new file");
        assert!(dest.exists(), "Destination should exist");
        assert_eq!(fs::read_to_string(&dest).unwrap(), "hello");
    }

    #[test]
    fn test_copy_if_newer_same_content() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dest.txt");

        fs::write(&src, "hello").unwrap();
        fs::copy(&src, &dest).unwrap();

        // Small delay to ensure timestamps could differ if copied
        std::thread::sleep(std::time::Duration::from_millis(10));

        let copied = copy_if_newer(&src, &dest).unwrap();
        assert!(!copied, "Should not copy identical file");
    }

    #[test]
    fn test_copy_if_newer_different_size() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dest.txt");

        fs::write(&src, "hello world").unwrap();
        fs::write(&dest, "hi").unwrap();

        let copied = copy_if_newer(&src, &dest).unwrap();
        assert!(copied, "Should copy when sizes differ");
        assert_eq!(fs::read_to_string(&dest).unwrap(), "hello world");
    }

    #[test]
    fn test_copy_if_newer_source_newer() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dest.txt");

        // Create dest first
        fs::write(&dest, "old").unwrap();

        // Wait a bit, then create src
        std::thread::sleep(std::time::Duration::from_millis(100));
        fs::write(&src, "new").unwrap();

        let copied = copy_if_newer(&src, &dest).unwrap();
        assert!(copied, "Should copy newer source");
        assert_eq!(fs::read_to_string(&dest).unwrap(), "new");
    }

    #[test]
    fn test_should_copy_file_nonexistent_dest() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dest.txt");

        fs::write(&src, "hello").unwrap();

        assert!(
            should_copy_file(&src, &dest),
            "Should copy when dest doesn't exist"
        );
    }

    /// After copy_if_newer, source and dest must have different inodes.
    /// This guarantees memory isolation: each box gets independent page cache
    /// entries and .text sections (whether reflink or regular copy was used).
    #[test]
    fn test_copy_if_newer_creates_distinct_inode() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().unwrap();
        let src = dir.path().join("binary");
        let dest = dir.path().join("binary-copy");

        fs::write(&src, "ELF-fake-binary-data").unwrap();

        let copied = copy_if_newer(&src, &dest).unwrap();
        assert!(copied);

        let src_ino = fs::metadata(&src).unwrap().ino();
        let dest_ino = fs::metadata(&dest).unwrap().ino();
        assert_ne!(
            src_ino, dest_ino,
            "Source and dest must have different inodes for memory isolation"
        );
    }

    /// Verify copy_if_newer produces byte-identical output for larger files,
    /// regardless of whether reflink or regular copy is used.
    #[test]
    fn test_copy_if_newer_large_file_byte_identical() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("large.bin");
        let dest = dir.path().join("large-copy.bin");

        // 4KB repeated pattern (simulates a small binary)
        let pattern: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        fs::write(&src, &pattern).unwrap();

        let copied = copy_if_newer(&src, &dest).unwrap();
        assert!(copied);

        let src_data = fs::read(&src).unwrap();
        let dest_data = fs::read(&dest).unwrap();
        assert_eq!(src_data.len(), dest_data.len(), "File sizes must match");
        assert_eq!(src_data, dest_data, "File contents must be byte-identical");
    }

    /// A copied executable must stay executable.
    ///
    /// The regression this pins: `reflink` creates the destination with the
    /// process default mode rather than the source's, so on a filesystem that
    /// supports reflink (btrfs, APFS, xfs with reflink=1) the per-box copy of
    /// `boxlite-shim` came out `0664` and `bwrap` could not `execvp` it, while
    /// the same code on ext4 fell back to `fs::copy` and produced `0755`.
    #[cfg(unix)]
    #[test]
    fn test_copy_if_newer_preserves_executable_bit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let src = dir.path().join("boxlite-shim");
        let dest = dir.path().join("boxlite-shim-copy");

        fs::write(&src, "ELF-fake-binary-data").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(copy_if_newer(&src, &dest).unwrap());

        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o755,
            "copied binary must carry the source mode, got {mode:o}"
        );
    }

    /// The mode is copied, not widened: a non-executable source stays
    /// non-executable.
    #[cfg(unix)]
    #[test]
    fn test_copy_if_newer_does_not_add_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let src = dir.path().join("libkrunfw.so.5");
        let dest = dir.path().join("libkrunfw-copy.so.5");

        fs::write(&src, "not-executable").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(copy_if_newer(&src, &dest).unwrap());

        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "copy must not widen the mode, got {mode:o}");
    }

    /// Re-copying over a stale destination restores the source mode too — the
    /// destination may have been left non-executable by an older BoxLite.
    #[cfg(unix)]
    #[test]
    fn test_copy_if_newer_repairs_mode_of_stale_destination() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let src = dir.path().join("boxlite-shim");
        let dest = dir.path().join("boxlite-shim-copy");

        fs::write(&dest, "old").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o664)).unwrap();

        fs::write(&src, "ELF-fake-binary-data").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            copy_if_newer(&src, &dest).unwrap(),
            "sizes differ, must copy"
        );

        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755, "stale destination must be re-permissioned");
    }
}
