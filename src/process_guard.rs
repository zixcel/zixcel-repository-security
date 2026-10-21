//! Supervise only an owned local child. Sampling is not an OS memory sandbox.
use crate::{Result, require};
use std::{
    fs,
    path::Path,
    process::{Child, Command, ExitStatus},
    time::{Duration, Instant},
};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn rss(status: &str) -> Result<u64> {
    let Some(line) = status.lines().find(|s| s.starts_with("VmRSS:")) else {
        // A process already exiting can have no resident-memory field.
        return Ok(0);
    };
    let fields = line.split_whitespace().collect::<Vec<_>>();
    require(fields.len() == 3 && fields[2] == "kB")?;
    fields[1]
        .parse::<u64>()?
        .checked_mul(1024)
        .ok_or_else(|| "invalid RSS".into())
}
pub(crate) fn run(
    command: &mut Command,
    report: &Path,
    timeout: Duration,
    bytes: u64,
) -> Result<ExitStatus> {
    supervise(command, report, timeout, bytes)
}
fn supervise(
    command: &mut Command,
    report: &Path,
    timeout: Duration,
    bytes: u64,
) -> Result<ExitStatus> {
    let mut child = OwnedChild(command.spawn()?);
    let started = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(status);
        }
        require(started.elapsed() < timeout).map_err(|_| "child timed out")?;
        match fs::symlink_metadata(report) {
            Ok(meta) => require(meta.is_file() && !meta.is_symlink() && meta.len() <= bytes)
                .map_err(|_| "child output exceeded its budget")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        #[cfg(target_os = "linux")]
        match fs::read_to_string(format!("/proc/{}/status", child.0.id())) {
            Ok(status) => require(rss(&status)? <= 512 * 1024 * 1024)
                .map_err(|_| "child resident memory exceeded its observed budget")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
#[path = "process_guard_tests.rs"]
mod tests;
