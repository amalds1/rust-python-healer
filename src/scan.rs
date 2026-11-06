use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::json;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    thread,
};

const IGNORE_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "target",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "dist",
    "build",
];

#[derive(Serialize)]
struct FileFinding {
    path: String,
    status: String,
    error_type: Option<String>,
    message: Option<String>,
    line: Option<usize>,
}

fn discover(path: &Path, files: &mut Vec<PathBuf>, limit: usize, depth: usize) -> Result<()> {
    if depth > 16 {
        bail!("maximale diepte 16 overschreden: {}", path.display());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if path.extension().is_some_and(|s| s == "py") {
            files.push(path.to_path_buf());
            if files.len() > limit {
                bail!("maximaal {limit} Python-bestanden toegestaan");
            }
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    let mut entries = fs::read_dir(path)?
        .map(|r| r.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    for child in entries {
        let name = child.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if IGNORE_DIRS.contains(&name) {
            continue;
        }
        discover(&child, files, limit, depth + 1)?;
    }
    Ok(())
}

/// Obtain one immutable copy of a discovered file before invoking any helper.
/// The selected path is never handed to Python after this operation.
#[cfg(target_os = "linux")]
fn linux_secure_snapshot(root: &Path, path: &Path) -> Result<Vec<u8>> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;

    let relative = path.strip_prefix(root).context("pad buiten projectroot")?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("onveilig pad buiten projectroot");
    }
    let relative = CString::new(relative.as_os_str().as_bytes())?;
    // O_NOFOLLOW also closes a root-directory replacement with a symlink
    // between canonicalization/discovery and this descriptor acquisition.
    let root_fd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        // NO_XDEV | NO_MAGICLINKS | NO_SYMLINKS | BENEATH (Linux openat2).
        resolve: 0x01 | 0x02 | 0x04 | 0x08,
    };
    // SAFETY: dirfd is a live directory, relative is nul-terminated and
    // `how` is a repr(C) open_how structure of the advertised size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            relative.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        bail!(
            "beveiligde bestandsopening geweigerd: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: openat2 returned a newly owned descriptor and ownership is
    // transferred exactly once to this File, also on subsequent errors.
    let mut handle = unsafe { fs::File::from_raw_fd(fd as i32) };
    let metadata = handle.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 4_000_000 {
        bail!("geen regulier, enkelvoudig gelinkt Python-bestand van maximaal 4 MB");
    }
    let mut output = Vec::new();
    handle.by_ref().take(4_000_001).read_to_end(&mut output)?;
    if output.len() > 4_000_000 {
        bail!("bestandsinhoud groeide tijdens lezen boven 4 MB");
    }
    Ok(output)
}

/// Snapshot the opened Windows leaf without following its reparse point.
/// Ancestor replacement races are NOT prevented by OPEN_REPARSE_POINT.
#[cfg(windows)]
fn windows_handle_snapshot(root: &Path, path: &Path) -> Result<Vec<u8>> {
    use std::ffi::c_void;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Component;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_TYPE_DISK: u32 = 1;
    const SOURCE_LIMIT: u64 = 4_000_000;

    // BY_HANDLE_FILE_INFORMATION: DWORDs and FILETIME pairs have 4-byte alignment.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileInformation {
        attributes: u32,
        creation_time: [u32; 2],
        last_access_time: [u32; 2],
        last_write_time: [u32; 2],
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(handle: *mut c_void, info: *mut FileInformation) -> i32;
        fn GetFileType(handle: *mut c_void) -> u32;
    }

    fn information(file: &fs::File) -> Result<FileInformation> {
        // SAFETY: FileInformation contains only integers, all-zero is valid;
        // the owned File keeps the HANDLE live throughout both API calls.
        let mut info: FileInformation = unsafe { std::mem::zeroed() };
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
            bail!("windows_snapshot_requires_disk_file");
        }
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("windows_snapshot_handle_information_failed");
        }
        Ok(info)
    }

    fn validate(info: &FileInformation) -> Result<u64> {
        if info.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            bail!("windows_snapshot_directory_or_reparse_point_refused");
        }
        if info.links != 1 {
            bail!("windows_snapshot_requires_single_link");
        }
        let size = (u64::from(info.size_high) << 32) | u64::from(info.size_low);
        if size > SOURCE_LIMIT {
            bail!("windows_snapshot_exceeds_source_budget");
        }
        Ok(size)
    }

    let relative = path.strip_prefix(root).context("pad buiten projectroot")?;
    if relative.as_os_str().is_empty()
        || relative.components().any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("onveilig pad buiten projectroot");
    }
    // Share only READ: existing write/delete opens cause this open to fail,
    // and new write/delete opens are denied while this handle remains alive.
    // OPEN_REPARSE_POINT applies to the leaf, not traversed parent directories.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .context("windows_snapshot_read_only_handle_open_failed")?;
    let before = information(&file)?;
    let size = validate(&before)?;
    let mut output = Vec::new();
    file.by_ref().take(SOURCE_LIMIT + 1).read_to_end(&mut output)?;
    if output.len() as u64 > SOURCE_LIMIT {
        bail!("windows_snapshot_grew_above_source_budget");
    }
    let after = information(&file)?;
    let final_size = validate(&after)?;
    if (before.volume_serial, before.index_high, before.index_low)
        != (after.volume_serial, after.index_high, after.index_low)
        || size != final_size
        || output.len() as u64 != size
        || before.last_write_time != after.last_write_time
    {
        bail!("windows_snapshot_identity_size_or_write_time_changed");
    }
    Ok(output)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn best_effort_snapshot(root: &Path, path: &Path) -> Result<Vec<u8>> {
    let relative = path.strip_prefix(root).context("pad buiten projectroot")?;
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            bail!("onveilig pad buiten projectroot");
        }
    }
    // Not equivalent to Linux openat2: concurrent path swaps remain unverified.
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("symlink geweigerd");
    }
    crate::validate_file_size(path)
}

fn secured_snapshot(root: &Path, path: &Path) -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        linux_secure_snapshot(root, path)
    }
    #[cfg(windows)]
    {
        windows_handle_snapshot(root, path)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        best_effort_snapshot(root, path)
    }
}

pub fn project(
    root: &Path,
    python: &str,
    limit: usize,
    workers: usize,
) -> Result<serde_json::Value> {
    if limit == 0 || limit > 10_000 {
        bail!("--limit moet tussen 1 en 10000 liggen");
    }
    if workers == 0 || workers > 16 {
        bail!("--workers moet tussen 1 en 16 liggen");
    }
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        bail!("een symlink als projectroot is niet toegestaan");
    }
    let root =
        fs::canonicalize(root).with_context(|| format!("niet gevonden: {}", root.display()))?;
    let mut files = Vec::new();
    discover(&root, &mut files, limit, 0)?;
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::new());

    thread::scope(|scope| {
        for _ in 0..workers.min(files.len()) {
            let files = &files;
            let next = &next;
            let results = &results;
            let root = &root;
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(file) = files.get(index) else { break };
                let finding = match secured_snapshot(root, file).and_then(|source| {
                    let temporary = tempfile::Builder::new().suffix(".py").tempfile()?;
                    fs::write(temporary.path(), source)?;
                    crate::compile_only(temporary.path(), python)
                }) {
                    Ok(result) => FileFinding {
                        path: file.display().to_string(),
                        status: result.compile,
                        error_type: result.error_type,
                        message: result.message,
                        line: result.line,
                    },
                    Err(exc) => FileFinding {
                        path: file.display().to_string(),
                        status: "NOT_RUN".into(),
                        error_type: Some("AnalysisError".into()),
                        message: Some(exc.to_string()),
                        line: None,
                    },
                };
                results.lock().expect("scan result mutex").push(finding);
            });
        }
    });
    let mut items = results.into_inner().expect("scan result mutex");
    items.sort_by(|a, b| a.path.cmp(&b.path));
    let passed = items.iter().filter(|f| f.status == "PASS").count();
    let failed = items.iter().filter(|f| f.status == "FAIL").count();
    let not_run = items.len() - passed - failed;
    Ok(json!({
        "root": root.display().to_string(),
        "files": items.len(), "passed": passed, "failed": failed,
        "not_run": not_run, "workers": workers,
        "status": if items.is_empty() { "NOT_RUN" }
                  else if failed == 0 && not_run == 0 { "PASS" }
                  else { "INCOMPLETE" },
        "findings": items,
        "note": "Compile-only: no project code execution or behavioral proof",
        "path_protection": if cfg!(target_os = "linux") {
            "OPENAT2_NO_SYMLINKS_BENEATH_NO_XDEV_AND_HARDLINK_REFUSAL"
        } else if cfg!(windows) {
            "WINDOWS_LEAF_HANDLE_SINGLE_LINK_NO_REPARSE_ANCESTOR_TOCTOU_UNVERIFIED"
        } else {
            "BEST_EFFORT_NO_TOCTOU_GUARANTEE"
        },
    }))
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn windows_snapshot_reads_exact_plain_file_bytes() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("plain.py");
        let bytes = b"value = 42\r\n# fixed own fixture\r\n";
        fs::write(&file, bytes).unwrap();
        assert_eq!(secured_snapshot(root.path(), &file).unwrap(), bytes);
    }

    #[test]
    fn windows_snapshot_rejects_external_hardlink_before_reading() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let source = outside.path().join("outside.py");
        fs::write(&source, b"invalid syntax beyond project boundary !!!\n").unwrap();
        let link = root.path().join("hardlink.py");
        fs::hard_link(&source, &link).unwrap();
        let error = secured_snapshot(root.path(), &link).unwrap_err();
        assert_eq!(error.to_string(), "windows_snapshot_requires_single_link");
    }

    #[test]
    fn windows_snapshot_refuses_file_with_existing_write_handle() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("writer.py");
        fs::write(&path, b"value = 42\n").unwrap();
        let writer = fs::OpenOptions::new().write(true).share_mode(7).open(&path).unwrap();
        assert!(secured_snapshot(root.path(), &path).is_err());
        drop(writer);
        assert_eq!(secured_snapshot(root.path(), &path).unwrap(), b"value = 42\n");
    }

    #[test]
    fn windows_snapshot_refuses_budget_excess_and_relative_escape() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("oversized.py");
        fs::File::create(&path).unwrap().set_len(4_000_001).unwrap();
        assert_eq!(secured_snapshot(root.path(), &path).unwrap_err().to_string(),
                   "windows_snapshot_exceeds_source_budget");
        assert!(secured_snapshot(root.path(), &root.path().join("../outside.py")).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn openat2_snapshot_reads_plain_file_without_running_it() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("sample.py");
        fs::write(&file, b"open('/tmp/never_run', 'w')\n").unwrap();
        assert_eq!(
            secured_snapshot(root.path(), &file).unwrap(),
            b"open('/tmp/never_run', 'w')\n"
        );
    }

    #[test]
    fn openat2_rejects_parent_and_external_directory_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("escape.py"), b"secret\n").unwrap();
        symlink(outside.path(), root.path().join("alias")).unwrap();
        assert!(secured_snapshot(root.path(), &root.path().join("alias/escape.py")).is_err());
        assert!(secured_snapshot(root.path(), &root.path().join("../escape.py")).is_err());
    }

    #[test]
    fn openat2_rejects_file_symlink_and_external_hardlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let foreign = outside.path().join("foreign.py");
        fs::write(&foreign, b"from outside\n").unwrap();
        symlink(&foreign, root.path().join("symlink.py")).unwrap();
        fs::hard_link(&foreign, root.path().join("hardlink.py")).unwrap();
        assert!(secured_snapshot(root.path(), &root.path().join("symlink.py")).is_err());
        assert!(secured_snapshot(root.path(), &root.path().join("hardlink.py")).is_err());
    }

    #[test]
    fn openat2_rejects_symlink_replacing_root_directory() {
        let parent = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("foreign.py"), b"from outside\n").unwrap();
        let swapped_root = parent.path().join("root");
        symlink(outside.path(), &swapped_root).unwrap();
        assert!(secured_snapshot(&swapped_root, &swapped_root.join("foreign.py")).is_err());
    }
}
