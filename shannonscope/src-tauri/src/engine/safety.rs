pub struct SafetyGuard;

impl SafetyGuard {
    pub fn validate_target(target: &str) -> Result<(), String> {
        let blacklisted = ["/dev/sda", "/dev/sdb", "/dev/nvme0n1", "/dev/root"];
        for bad in blacklisted.iter() {
            if target == *bad {
                panic!("CRITICAL SECURITY VIOLATION: Attempted to target host boot drive {}!", bad);
            }
        }

        let whitelisted = ["test_drive.raw", "/dev/loop", "/dev/sdc", "/dev/sdd"];
        let mut is_safe = false;
        for good in whitelisted.iter() {
            if target.contains(good) {
                is_safe = true;
                break;
            }
        }

        // Allow regular file paths for Module 2, but block raw blocks if not whitelisted
        if !is_safe && target.starts_with("/dev/") {
            return Err(format!("SECURITY ABORT: Target block device {} is not explicitly whitelisted.", target));
        }

        Ok(())
    }
}
