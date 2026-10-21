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
    assert!(error.to_string().contains("output exceeded"));
    let id = fs::read_to_string(pid).unwrap();
    assert!(!Path::new(&format!("/proc/{}", id.trim())).exists());
}
