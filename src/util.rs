pub fn make_alphanumeric(s: &str) -> String {
    s.replace(
        |c| !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')),
        "_",
    )
}
