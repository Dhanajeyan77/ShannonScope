use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use crate::engine::safety::SafetyGuard;

// Linux BLKDISCARD ioctl command binding: _IO(0x12, 119)
const BLKDISCARD: u64 = 0x1277;

pub enum WipeProfile {
    NistClear,      // Single pass zero
    Dod522022M,     // 3-Pass: 0x00, 0xFF, Random
    HardwarePurge,  // BLKDISCARD for SSD / flash
}

pub struct SanitizerEngine;

impl SanitizerEngine {
    pub fn is_rotational(dev_path: &str) -> bool {
        let dev_name = Path::new(dev_path).file_name().and_then(|n| n.to_str()).unwrap_or("");
        let sys_path = format!("/sys/block/{}/queue/rotational", dev_name);
        if let Ok(content) = std::fs::read_to_string(sys_path) {
            return content.trim() == "1";
        }
        false // Default to non-rotational safe handling
    }

    pub fn sanitize_target(target_path: &str, profile: WipeProfile) -> Result<bool, String> {
        SafetyGuard::validate_target(target_path)?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_SYNC) // Bypass OS buffer caches
            .open(target_path)
            .map_err(|e| format!("Failed to open target with direct sync flags: {e}"))?;

        let total_bytes = file.metadata().map_err(|e| e.to_string())?.len();

        match profile {
            WipeProfile::HardwarePurge => {
                println!("[+] Invoking Kernel Hardware Discard ioctl on {}", target_path);
                let range: [u64; 2] = [0, total_bytes];
                let fd = file.as_raw_fd();
                let ret = unsafe { libc::ioctl(fd, BLKDISCARD, &range) };
                if ret != 0 {
                    return Err(format!("BLKDISCARD failed with error code {}", std::io::Error::last_os_error()));
                }
                println!("[+] Hardware deallocation signal committed to device controller.");
            },
            WipeProfile::NistClear => {
                Self::write_pass(&mut file, total_bytes, 0x00, "NIST-Clear [0x00]")?;
            },
            WipeProfile::Dod522022M => {
                Self::write_pass(&mut file, total_bytes, 0x00, "DoD Pass 1/3 [0x00]")?;
                Self::write_pass(&mut file, total_bytes, 0xFF, "DoD Pass 2/3 [0xFF]")?;
                Self::write_random_pass(&mut file, total_bytes, "DoD Pass 3/3 [PRNG Random]")?;
            }
        }

        let expected_pattern = match profile {
            WipeProfile::NistClear => Some(0x00),
            WipeProfile::HardwarePurge => Some(0x00), // Assuming discard zeroes the block
            WipeProfile::Dod522022M => None, // Random data
        };

        // Run post-wipe verification sampling
        Self::verify_wipe_state(&mut file, total_bytes, 4096, expected_pattern)
    }

    fn write_pass(file: &mut File, total: u64, pattern: u8, label: &str) -> Result<(), String> {
        println!("[+] Starting Write Pass: {}", label);
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let chunk_size = 2 * 1024 * 1024; // 2 MB blocks
        let buffer = vec![pattern; chunk_size];
        let mut written: u64 = 0;

        while written < total {
            let to_write = (total - written).min(chunk_size as u64) as usize;
            file.write_all(&buffer[..to_write]).map_err(|e| e.to_string())?;
            written += to_write as u64;
        }
        file.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn write_random_pass(file: &mut File, total: u64, label: &str) -> Result<(), String> {
        println!("[+] Starting Random Pass: {}", label);
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let chunk_size = 1024 * 1024;
        let mut buffer = vec![0u8; chunk_size];
        let mut written: u64 = 0;

        while written < total {
            let to_write = (total - written).min(chunk_size as u64) as usize;
            // Fill slice with fast pseudo-random values
            for byte in buffer[..to_write].iter_mut() {
                *byte = rand::random::<u8>();
            }
            file.write_all(&buffer[..to_write]).map_err(|e| e.to_string())?;
            written += to_write as u64;
        }
        file.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn verify_wipe_state(file: &mut File, total: u64, stride_step: u64, expected_pattern: Option<u8>) -> Result<bool, String> {
        println!("[+] Performing Stride Verification across {} bytes (Sampling every {} bytes)", total, stride_step);
        let mut cursor = 0;
        let mut sample_block = [0u8; 512];

        while cursor < total {
            file.seek(SeekFrom::Start(cursor)).map_err(|e| e.to_string())?;
            let read_bytes = file.read(&mut sample_block).map_err(|e| e.to_string())?;
            if read_bytes == 0 { break; }

            if let Some(pattern) = expected_pattern {
                for &b in &sample_block[..read_bytes] {
                    if b != pattern {
                        return Ok(false); // Unexpected byte encountered
                    }
                }
            }
            cursor += stride_step;
        }
        Ok(true)
    }
}
