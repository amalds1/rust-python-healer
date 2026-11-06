use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Native interpreter name; callers can still select an explicit interpreter path.
pub const DEFAULT_PYTHON: &str = if cfg!(windows) { "python" } else { "python3" };

/// Bounds execution time and output size for trusted analysis tools.
///
/// Writes child output to temporary files to avoid stdout pipe deadlock. This
/// does not provide a sandbox or memory isolation for arbitrary user code.
pub fn bounded_output(mut command: Command, timeout: Duration, max_bytes: u64) -> Result<Output> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    command
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));
    let mut child = command.spawn().context("hulpproces kon niet starten")?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "hulpproces heeft de tijdlimiet van {}s overschreden",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(25));
    };
    if stdout.metadata()?.len() > max_bytes || stderr.metadata()?.len() > max_bytes {
        bail!("hulpproces produceerde meer dan {max_bytes} bytes uitvoer");
    }
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.read_to_end(&mut out)?;
    stderr.read_to_end(&mut err)?;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}

/// An opaque error-context summary: never interpolate a child's raw stderr
/// into the main CLI's diagnostics or the caller's audit log.
pub fn redacted_stderr(value: &[u8]) -> String {
    format!(
        "stderr_sha256={} bytes={}",
        hex::encode(Sha256::digest(value)),
        value.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_bounded_output() {
        let mut command = Command::new(DEFAULT_PYTHON);
        command.args(["-I", "-S", "-c", "print('bounded')"]);
        let output = bounded_output(command, Duration::from_secs(5), 1024).unwrap();
        assert!(output.status.success());
        let expected: &[u8] = if cfg!(windows) { b"bounded\r\n" } else { b"bounded\n" };
        assert_eq!(output.stdout, expected);
    }

    #[test]
    fn rejects_excessive_output() {
        let mut command = Command::new(DEFAULT_PYTHON);
        command.args(["-I", "-S", "-c", "print('x' * 10000)"]);
        let result = bounded_output(command, Duration::from_secs(5), 100);
        assert!(result.is_err());
    }

    #[test]
    fn terminates_slow_subprocess() {
        let mut command = Command::new(DEFAULT_PYTHON);
        command.args(["-I", "-S", "-c", "import time; time.sleep(4)"]);
        let start = Instant::now();
        let result = bounded_output(command, Duration::from_millis(100), 100);
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn stderr_redaction_never_echoes_secrets_or_invalid_utf8() {
        let raw = b"private-token=api-v26-very-secret\nclient@example.org\xff";
        let report = redacted_stderr(raw);
        assert!(report.starts_with("stderr_sha256="));
        assert!(report.contains(&format!("bytes={}", raw.len())));
        assert!(!report.contains("api-v26"));
        assert!(!report.contains("client@example.org"));
        assert_eq!(report, redacted_stderr(raw));
        assert_ne!(report, redacted_stderr(b"different token"));
    }

    #[test]
    fn raw_child_stderr_is_kept_private_in_failure_context() {
        let mut command = Command::new(DEFAULT_PYTHON);
        command.args([
            "-I",
            "-S",
            "-c",
            "import sys;sys.stderr.write('sensitive-output');sys.exit(4)",
        ]);
        let output = bounded_output(command, Duration::from_secs(5), 1024).unwrap();
        assert!(!output.status.success());
        let diagnostic = format!("Python fail: {}", redacted_stderr(&output.stderr));
        assert!(!diagnostic.contains("sensitive-output"));
        assert!(diagnostic.contains("stderr_sha256="));
    }
}
