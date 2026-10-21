//! Bounded artifact extraction. Retain required notices without trusting paths.
use crate::{Result, require};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    path::{Component, Path},
};
pub(crate) struct Contents {
    pub binary: Vec<u8>,
    pub notices: BTreeMap<String, Vec<u8>>,
}
pub(crate) fn unpack(bytes: &[u8]) -> Result<Contents> {
    let reader = flate2::read::GzDecoder::new(Cursor::new(bytes)).take(128 * 1024 * 1024 + 1);
    let mut tar = tar::Archive::new(reader);
    let mut binary = None;
    let mut notices = BTreeMap::new();
    let mut budget = 16 * 1024 * 1024;
    for (count, entry) in tar.entries()?.enumerate() {
        require(count < 4096)?;
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        require(path.components().all(|c| matches!(c, Component::Normal(_))))?;
        let kind = entry.header().entry_type();
        require(kind.is_file() || kind.is_dir())?;
        if kind.is_dir() {
            continue;
        }
        if path == Path::new("gitleaks") {
            require(binary.is_none() && entry.size() <= 64 * 1024 * 1024)?;
            let mut content = Vec::new();
            entry
                .by_ref()
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut content)?;
            require(content.len() <= 64 * 1024 * 1024)?;
            binary = Some(content);
        } else if path.starts_with("licenses")
            || ["LICENSE", "Go-runtime-LICENSE", "NOTICE"]
                .iter()
                .any(|p| path == Path::new(p))
        {
            let name = path.to_str().ok_or("invalid notice path")?.to_owned();
            require(
                entry.size() <= 1024 * 1024 && notices.len() < 1024 && !notices.contains_key(&name),
            )?;
            let mut content = Vec::new();
            entry
                .by_ref()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut content)?;
            require(content.len() <= budget && content.len() <= 1024 * 1024)?;
            budget -= content.len();
            notices.insert(name, content);
        }
    }
    // Consume gzip EOF/CRC and enforce the aggregate expanded-stream budget.
    let mut reader = tar.into_inner();
    std::io::copy(&mut reader, &mut std::io::sink())?;
    require(
        reader.limit() > 0
            && notices.contains_key("LICENSE")
            && notices.contains_key("Go-runtime-LICENSE")
            && notices.keys().any(|p| p.starts_with("licenses/")),
    )?;
    Ok(Contents {
        binary: binary.ok_or("executable member missing")?,
        notices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive(duplicate: bool) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for name in [
            "gitleaks",
            "LICENSE",
            "Go-runtime-LICENSE",
            "licenses/dependency/LICENSE",
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, name, &b"test"[..]).unwrap();
            if duplicate {
                tar.append_data(&mut header, name, &b"test"[..]).unwrap();
            }
        }
        let bytes = tar.into_inner().unwrap();
        use std::io::Write;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&bytes).unwrap();
        gzip.finish().unwrap()
    }
    #[test]
    fn preserves_notices_and_rejects_duplicate_members() {
        let contents = unpack(&archive(false)).unwrap();
        assert_eq!(contents.binary, b"test");
        assert_eq!(contents.notices.len(), 3);
        assert!(unpack(&archive(true)).is_err());
    }
    #[test]
    fn truncated_or_bad_crc_archive_cannot_install() {
        let mut bytes = archive(false);
        bytes.pop();
        assert!(unpack(&bytes).is_err());
        let mut bytes = archive(false);
        let end = bytes.len();
        bytes[end - 8] ^= 1;
        assert!(unpack(&bytes).is_err());
    }
}
