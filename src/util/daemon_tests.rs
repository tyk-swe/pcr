use super::*;

#[cfg(unix)]
#[test]
fn ensure_daemonized_foreground_unix() {
    assert!(ensure_daemonized(true).is_ok());
}

#[cfg(not(unix))]
#[test]
fn ensure_daemonized_foreground_non_unix() {
    assert!(ensure_daemonized(true).is_ok());
}

#[cfg(not(unix))]
#[test]
fn ensure_daemonized_background_non_unix_fails() {
    let result = ensure_daemonized(false);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("only supported on Unix"));
}
