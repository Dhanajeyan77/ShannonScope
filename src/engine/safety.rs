use std::path::Path;
use std::fs;

pub struct SafetyGuard;

impl SafetyGuard {
    pub fn validate_target(target_path: &str) -> Result<(), String> {
        let path = Path::new(target_path);
        
        // 1. Resolve canonical path to prevent symlink traversal
        let canonical = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => path.to_path_buf(), // Permit validation on pre-created file paths
        };
        let target_str = canonical.to_string_lossy();

        // 2. Blacklist critical host root devices and primary NVMe drives
        let forbidden_targets = [
            "/dev/sda", "/dev/sdb", "/dev/nvme0n1", 
            "/dev/vda", "/dev/mapper", "/dev/root"
        ];
        
        for forbidden in forbidden_targets {
            if target_str == forbidden || target_str.starts_with(&format!("{forbidden}p")) {
                return Err(format!(
                    "CRITICAL SAFETY ABORT: Target '{}' matches protected host drive '{}'. Execution blocked.",
                    target_str, forbidden
                ));
            }
        }

        // 3. Explicit whitelist constraint for testing
        let is_loopback = target_str.ends_with("test_drive.raw") || target_str.contains("/dev/loop");
        let is_whitelisted_usb = target_str.contains("/dev/sdc") || target_str.contains("/dev/sdd");

        if !is_loopback && !is_whitelisted_usb {
            return Err(format!(
                "SAFETY RESTRICTION: Target '{}' is not an approved test fixture. Must end with 'test_drive.raw' or match assigned removable USB nodes.",
                target_str
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "CRITICAL SAFETY ABORT: Target '/dev/sda' matches protected host drive '/dev/sda'. Execution blocked.")]
    fn test_forbidden_drive_panics() {
        SafetyGuard::validate_target("/dev/sda").unwrap();
    }

    #[test]
    fn test_allowed_loopback_succeeds() {
        // Assume test_drive.raw exists or is resolved correctly by path
        SafetyGuard::validate_target("tests/test_drive.raw").unwrap();
    }
}
