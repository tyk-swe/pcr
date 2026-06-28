use super::*;
use std::path::PathBuf;

#[test]
fn privilege_error_display_raw_socket_unavailable() {
    let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
    let err = PrivilegeError::RawSocketUnavailable { source: io_error };
    let msg = err.to_string();
    #[cfg(target_os = "linux")]
    assert!(msg.contains("CAP_NET_RAW capability not available"));
    #[cfg(not(target_os = "linux"))]
    assert!(msg.contains("raw socket"));
}

#[test]
fn privilege_error_display_missing_capability() {
    let binary_path = PathBuf::from("/usr/bin/packetcraftr");
    let err = PrivilegeError::MissingCapability {
        binary: binary_path.clone(),
        source: None,
    };
    let msg = err.to_string();
    assert!(msg.contains("require root privileges"));
    assert!(msg.contains(binary_path.to_str().unwrap()));
}
