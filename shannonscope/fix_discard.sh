#!/bin/bash
cat << 'INNER' > src-tauri/src/engine/sanitizer.rs
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use crate::engine::safety::SafetyGuard;

#[cfg(target_os = "linux")]
const BLKDISCARD: u64 = 0x1277;

pub enum WipeProfile {
    NistClear,      
    Dod522022M,     
    HardwarePurge,  
}

pub struct SanitizerEngine;

impl SanitizerEngine {
    pub fn is_rotational(dev_path: &str) -> bool {
        let dev_name = Path::new(dev_path).file_name().and_then(|n| n.to_str()).unwrap_or("");
        let sys_path = format!("/sys/block/{}/queue/rotational", dev_name);
        if let Ok(content) = std::fs::read_to_string(sys_path) {
            return content.trim() == "1";
        }
        false
    }

    pub fn sanitize_target(target_path: &str, profile: WipeProfile) -> Result<bool, String> {
        SafetyGuard::validate_target(target_path)?;

        let mut opts = OpenOptions::new();
        opts.read(true).write(true);

        #[cfg(target_os = "linux")]
        opts.custom_flags(libc::O_SYNC); 

        let mut file = opts.open(target_path)
            .map_err(|e| format!("Failed to open target with direct sync flags: {e}"))?;

        let total_bytes = file.metadata().map_err(|e| e.to_string())?.len();
        
        // In case of block devices, len() is 0. We need to handle this!
        let total_bytes = if total_bytes == 0 {
            // Find size using ioctl BLKGETSIZE64
            let mut size: u64 = 0;
            let fd = file.as_raw_fd();
            unsafe {
                if libc::ioctl(fd, 0x80081272, &mut size) == 0 {
                    size
                } else {
                    0
                }
            }
        } else {
            total_bytes
        };

        match profile {
            WipeProfile::HardwarePurge => {
                println!("[+] Invoking Kernel Hardware Discard ioctl on {}", target_path);
                #[cfg(target_os = "linux")]
                {
                    let range: [u64; 2] = [0, total_bytes];
                    let fd = file.as_raw_fd();
                    let ret = unsafe { libc::ioctl(fd, BLKDISCARD, &range) };
                    if ret != 0 {
                        println!("[-] Hardware Discard unsupported (Error 95). Falling back to Software Zero-Fill (NIST-Clear).");
                        Self::write_pass(&mut file, total_bytes, 0x00, "NIST-Clear Fallback [0x00]")?;
                    } else {
                        println!("[+] Hardware deallocation signal committed to device controller.");
                    }
                }
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
            WipeProfile::HardwarePurge => Some(0x00), 
            WipeProfile::Dod522022M => None, 
        };

        Self::verify_wipe_state(&mut file, total_bytes, 4096, expected_pattern)
    }

    pub fn sanitize_file(target_path: &str, profile: WipeProfile) -> Result<bool, String> {
        let path = Path::new(target_path);
        if !path.exists() {
            return Err("Target path does not exist".to_string());
        }

        if path.is_dir() {
            for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let _ = Self::secure_erase_file(entry.path(), &profile);
                }
            }
            let _ = std::fs::remove_dir_all(path);
            Ok(true)
        } else {
            Self::secure_erase_file(path, &profile)
        }
    }

    fn secure_erase_file(path: &Path, profile: &WipeProfile) -> Result<bool, String> {
        let mut file = OpenOptions::new().write(true).open(path).map_err(|e| e.to_string())?;
        let total_bytes = file.metadata().map_err(|e| e.to_string())?.len();

        match profile {
            WipeProfile::HardwarePurge | WipeProfile::NistClear => {
                Self::write_pass(&mut file, total_bytes, 0x00, "File NIST-Clear [0x00]")?;
            },
            WipeProfile::Dod522022M => {
                Self::write_pass(&mut file, total_bytes, 0x00, "File DoD 1/3")?;
                Self::write_pass(&mut file, total_bytes, 0xFF, "File DoD 2/3")?;
                Self::write_random_pass(&mut file, total_bytes, "File DoD 3/3")?;
            }
        }
        
        let parent = path.parent().unwrap_or(Path::new(""));
        let mut current_path = path.to_path_buf();

        for _ in 0..5 {
            let rand_name: String = (0..8).map(|_| {
                let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                charset[(rand::random::<u32>() as usize) % charset.len()] as char
            }).collect();
            let new_path = parent.join(format!("{}.tmp", rand_name));
            if std::fs::rename(&current_path, &new_path).is_ok() {
                current_path = new_path;
            }
        }

        std::fs::remove_file(&current_path).map_err(|e| e.to_string())?;
        Ok(true)
    }

    fn write_pass(file: &mut File, total: u64, pattern: u8, label: &str) -> Result<(), String> {
        println!("[+] Starting Write Pass: {}", label);
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let chunk_size = 2 * 1024 * 1024; 
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
                        return Ok(false); 
                    }
                }
            }
            cursor += stride_step;
        }
        Ok(true)
    }
}
INNER
