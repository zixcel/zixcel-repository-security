//! Supervise only the detector child. Sampling is not an OS memory sandbox.
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
pub(crate) fn run(command: &mut Command, report: &Path) -> Result<ExitStatus> {
    supervise(
        command,
        report,
        Duration::from_secs(120),
        crate::MAX_FILE as u64,
    )
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
        require(started.elapsed() < timeout).map_err(|_| "detector timed out")?;
        match fs::symlink_metadata(report) {
            Ok(meta) => require(meta.is_file() && !meta.is_symlink() && meta.len() <= bytes)
                .map_err(|_| "detector report exceeded its budget")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        #[cfg(target_os = "linux")]
        match fs::read_to_string(format!("/proc/{}/status", child.0.id())) {
            Ok(status) => require(rss(&status)? <= 512 * 1024 * 1024)
                .map_err(|_| "detector resident memory exceeded its observed budget")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    fn child(script: &str, pid: &Path, report: &Path) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script, "detector-test"])
            .arg(pid)
            .arg(report)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }
    #[test]
    fn rss_units_and_overflow_are_checked() {
        assert_eq!(rss("Name: test\nVmRSS: 42 kB\n").unwrap(), 42 * 1024);
        assert!(rss("VmRSS: 42 MB").is_err());
        assert!(rss("VmRSS: 18446744073709551615 kB").is_err());
        assert_eq!(rss("State: Z").unwrap(), 0);
    }
    #[test]
    fn timeout_kills_and_reaps_only_the_owned_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        let report = dir.path().join("report");
        let mut cmd = child(
            "echo $$ > \"$1\"; trap '' TERM; while :; do :; done",
            &pid,
            &report,
        );
        assert!(supervise(&mut cmd, &report, Duration::from_millis(80), 64).is_err());
        let id = fs::read_to_string(pid).unwrap();
        assert!(!Path::new(&format!("/proc/{}", id.trim())).exists());
    }
    #[test]
    fn oversized_report_stops_a_running_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        let report = dir.path().join("report");
        let mut cmd = child(
            "echo $$ > \"$1\"; printf 'too-long' > \"$2\"; while :; do :; done",
            &pid,
            &report,
        );
        let error = supervise(&mut cmd, &report, Duration::from_secs(2), 4).unwrap_err();
        assert!(error.to_string().contains("report exceeded"));
        let id = fs::read_to_string(pid).unwrap();
        assert!(!Path::new(&format!("/proc/{}", id.trim())).exists());
    }
}
