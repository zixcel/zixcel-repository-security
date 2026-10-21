use std::io::Write;
use zixcel_repository_observer::Result;
pub fn emit(value: serde_json::Value) -> Result<()> {
    write_to(&value, &mut std::io::stdout().lock())
}
fn write_to(value: &serde_json::Value, writer: &mut impl Write) -> Result<()> {
    // Compact output keeps indentation from expanding a deeply nested API body.
    let mut bytes = serde_json::to_vec(value).map_err(|_| "serialization")?;
    if bytes.len() >= 1024 * 1024 {
        return Err("output_limit");
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .and_then(|()| writer.flush())
        .map_err(|_| "output_unavailable")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_output_is_rejected_before_any_write() {
        let mut sink = Vec::new();
        assert_eq!(
            write_to(&serde_json::json!("x".repeat(1024 * 1024)), &mut sink),
            Err("output_limit")
        );
        assert!(sink.is_empty());
    }
    #[test]
    fn broken_pipes_are_errors_instead_of_panics() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            write_to(&serde_json::json!({}), &mut Broken),
            Err("output_unavailable")
        );
    }
}
