pub(crate) fn encoded(input: &str) -> String {
    input
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub(crate) fn base(repository: &str) -> String {
    format!("/repos/{repository}")
}
pub(crate) fn page(path: &str, number: usize) -> String {
    format!(
        "{path}{}per_page=100&page={number}",
        if path.contains('?') { "&" } else { "?" }
    )
}
