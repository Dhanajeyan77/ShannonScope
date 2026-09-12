use std::process::Command;
use std::fs;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct SandboxResult {
    pub success: bool,
    pub mount_point: String,
    pub message: String,
}

pub struct SandboxEngine;

impl SandboxEngine {
    pub fn safe_mount(target_device: &str) -> Result<SandboxResult, String> {
        let mount_point = format!("/mnt/shannon_sandbox_{}", target_device.replace("/dev/", ""));
        
        if let Err(e) = fs::create_dir_all(&mount_point) {
            return Err(format!("Failed to create sandbox mount point: {}", e));
        }

        let _ = Command::new("umount")
            .arg(target_device)
            .output();

        let output = Command::new("mount")
            .arg("-o")
            .arg("ro,noexec,nodev,nosuid")
            .arg(target_device)
            .arg(&mount_point)
            .output()
            .map_err(|e| format!("Mount command failed: {}", e))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Safe Mount Failed (Drive might not have a filesystem): {}", err_msg));
        }

        Ok(SandboxResult {
            success: true,
            mount_point,
            message: format!("Device securely sandboxed at Read-Only, No-Exec mode."),
        })
    }

    pub fn safe_unmount(target_device: &str) -> Result<SandboxResult, String> {
        let mount_point = format!("/mnt/shannon_sandbox_{}", target_device.replace("/dev/", ""));
        
        let output = Command::new("umount")
            .arg(&mount_point)
            .output()
            .map_err(|e| format!("Unmount command failed: {}", e))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Safe Unmount Failed: {}", err_msg));
        }

        let _ = fs::remove_dir(&mount_point);

        Ok(SandboxResult {
            success: true,
            mount_point: "".to_string(),
            message: "Device safely released from Sandbox.".to_string(),
        })
    }
}
