#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
use engine::carver::CarverEngine;
use engine::sanitizer::{SanitizerEngine, WipeProfile};
use engine::audit::AuditLedger;
use engine::types::{CarvedArtifact, AuditEntry};
use engine::hardware::{get_drive_info, DriveInfo};

#[tauri::command]
async fn run_file_recovery(
    target: String, 
    output: String
) -> Result<Vec<CarvedArtifact>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _ = std::fs::create_dir_all("logs");
        let mut ledger = AuditLedger::init("logs/audit_chain.json");
        match CarverEngine::scan_and_carve(&target, &output) {
            Ok(results) => {
                ledger.append("CARVE", &target, "SUCCESS", "OPERATOR_ADMIN");
                Ok(results)
            },
            Err(e) => {
                ledger.append("CARVE", &target, &format!("FAILED: {e}"), "OPERATOR_ADMIN");
                Err(e)
            }
        }
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn run_drive_sanitization(
    target: String, 
    profile_type: String
) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _ = std::fs::create_dir_all("logs");
        let mut ledger = AuditLedger::init("logs/audit_chain.json");
        let profile = match profile_type.as_str() {
            "nist_clear" => WipeProfile::NistClear,
            "dod_3pass" => WipeProfile::Dod522022M,
            "hardware_purge" => WipeProfile::HardwarePurge,
            _ => return Err("Invalid wipe profile selected".to_string()),
        };

        match SanitizerEngine::sanitize_target(&target, profile) {
            Ok(true) => {
                ledger.append("WIPE", &target, "VERIFIED_CLEAN", "OPERATOR_ADMIN");
                Ok(true)
            },
            Ok(false) => {
                ledger.append("WIPE", &target, "VERIFICATION_FAILED", "OPERATOR_ADMIN");
                Ok(false)
            },
            Err(e) => {
                ledger.append("WIPE", &target, &format!("FAILED: {e}"), "OPERATOR_ADMIN");
                Err(e)
            }
        }
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn run_file_sanitization(
    target: String, 
    profile_type: String
) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _ = std::fs::create_dir_all("logs");
        let mut ledger = AuditLedger::init("logs/audit_chain.json");
        let profile = match profile_type.as_str() {
            "nist_clear" => WipeProfile::NistClear,
            "dod_3pass" => WipeProfile::Dod522022M,
            "hardware_purge" => WipeProfile::HardwarePurge,
            _ => return Err("Invalid wipe profile selected".to_string()),
        };

        match SanitizerEngine::sanitize_file(&target, profile) {
            Ok(true) => {
                ledger.append("FILE_WIPE", &target, "VERIFIED_CLEAN", "OPERATOR_ADMIN");
                Ok(true)
            },
            Err(e) => {
                ledger.append("FILE_WIPE", &target, &format!("FAILED: {e}"), "OPERATOR_ADMIN");
                Err(e)
            },
            _ => Ok(false)
        }
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
fn get_audit_trail() -> Vec<AuditEntry> {
    let ledger = AuditLedger::init("logs/audit_chain.json");
    ledger.entries
}

#[tauri::command]
async fn run_get_drive_info(target: String) -> Result<DriveInfo, String> {
    tauri::async_runtime::spawn_blocking(move || {
        get_drive_info(&target)
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
fn run_hex_view(path: String) -> Result<String, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    let mut buffer = [0u8; 256];
    let n = f.read(&mut buffer).unwrap_or(0);
    
    let mut hex_dump = String::new();
    for chunk in buffer[..n].chunks(16) {
        let hex_bytes: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let ascii_bytes: String = chunk.iter().map(|b| if *b >= 32 && *b <= 126 { *b as char } else { '.' }).collect();
        hex_dump.push_str(&format!("{}  |  {}\n", hex_bytes.join(" "), ascii_bytes));
    }
    Ok(hex_dump)
}

#[tauri::command]
fn run_export_report(artifacts: Vec<CarvedArtifact>, out_path: String) -> Result<(), String> {
    use printpdf::*;
    use std::fs::File;
    use std::io::BufWriter;
    
    let (doc, page1, layer1) = PdfDocument::new("Evidence Case Report", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);
    let font = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;

    current_layer.use_text("DIGITAL EVIDENCE RECOVERY REPORT", 20.0, Mm(30.0), Mm(270.0), &font);
    
    let mut y = 250.0;
    for (i, art) in artifacts.iter().enumerate() {
        if y < 30.0 { break; } // Basic page bound check for prototype
        current_layer.use_text(format!("{}. {} (Conf: {:.1}%) - {} bytes", i+1, art.file_type, art.confidence_score*100.0, art.size_bytes), 12.0, Mm(30.0), Mm(y), &font);
        y -= 6.0;
        current_layer.use_text(format!("   SHA256: {}", art.sha256_checksum), 10.0, Mm(30.0), Mm(y), &font);
        y -= 8.0;
    }

    let file = File::create(&out_path).map_err(|e| e.to_string())?;
    doc.save(&mut BufWriter::new(file)).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct DriveEnumInfo {
    pub path: String,
    pub size_gb: f64,
    pub is_removable: bool,
    pub is_system_drive: bool,
    pub label: String,
}

#[tauri::command]
fn enumerate_drives() -> Vec<DriveEnumInfo> {
    let mut drives = Vec::new();
    
    // Add logical partitions using sysinfo to detect system drive easily
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        if let Some(path) = disk.mount_point().to_str() {
            let is_sys = path == "/" || path == "C:\\";
            let size = disk.total_space() as f64 / 1_000_000_000.0;
            let tag = if disk.is_removable() { "Removable" } else { "Internal" };
            
            drives.push(DriveEnumInfo {
                path: path.to_string(),
                size_gb: size,
                is_removable: disk.is_removable(),
                is_system_drive: is_sys,
                label: format!("{} - {:.1}GB ({})", path, size, tag),
            });
        }
    }

    // Add physical raw paths manually for bare-metal forensic carving
    #[cfg(target_os = "linux")]
    {
        // Detect actual system drive path by checking where "/" is mounted
        let mut sys_device = String::new();
        for disk in disks.list() {
            if let Some(path) = disk.mount_point().to_str() {
                if path == "/" {
                    if let Some(dev) = disk.name().to_str() {
                        // e.g. /dev/nvme0n1p2 -> nvme0n1
                        let clean_dev = dev.replace("/dev/", "").chars().take_while(|c| !c.is_numeric() || dev.contains("nvme")).collect::<String>();
                        sys_device = clean_dev;
                    }
                }
            }
        }

        if let Ok(entries) = std::fs::read_dir("/sys/block/") {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("sd") || name.starts_with("nvme") {
                    let path = format!("/dev/{}", name);
                    
                    let mut size_gb = 0.0;
                    if let Ok(size_str) = std::fs::read_to_string(format!("/sys/block/{}/size", name)) {
                        if let Ok(sectors) = size_str.trim().parse::<u64>() {
                            size_gb = (sectors * 512) as f64 / 1_000_000_000.0;
                        }
                    }

                    let mut is_removable = false;
                    if let Ok(rem_str) = std::fs::read_to_string(format!("/sys/block/{}/removable", name)) {
                        is_removable = rem_str.trim() == "1";
                    }

                    let tag = if is_removable { "Removable" } else { "Internal/Physical" };
                    
                    // True heuristic: check if this block device matches the root mount
                    let is_sys = (!sys_device.is_empty() && name.starts_with(&sys_device[..2])) || (!is_removable && size_gb > 100.0);

                    drives.push(DriveEnumInfo {
                        path: path.clone(),
                        size_gb,
                        is_removable,
                        is_system_drive: is_sys,
                        label: format!("{} - {:.1}GB ({})", path, size_gb, tag),
                    });
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Mocking Windows physical drives for UI
        drives.push(DriveEnumInfo {
            path: r"\\.\PhysicalDrive0".to_string(),
            size_gb: 512.0,
            is_removable: false,
            is_system_drive: true,
            label: r"\\.\PhysicalDrive0 - 512.0GB (System)".to_string(),
        });
        drives.push(DriveEnumInfo {
            path: r"\\.\PhysicalDrive1".to_string(),
            size_gb: 32.0,
            is_removable: true,
            is_system_drive: false,
            label: r"\\.\PhysicalDrive1 - 32.0GB (Removable)".to_string(),
        });
    }

    // Sort to show external/removable drives at the top for forensics
    drives.sort_by(|a, b| b.is_removable.cmp(&a.is_removable));
    drives
}

#[tauri::command]
async fn open_folder(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&path)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&path)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub struct CloneResult {
    pub image_path: String,
    pub bytes_copied: u64,
    pub sha256_hash: String,
}

#[tauri::command]
async fn run_forensic_clone(target: String, output_dir: String) -> Result<CloneResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use std::fs::File;
        use std::io::{Read, Write};
        use sha2::{Sha256, Digest};

        let _ = std::fs::create_dir_all(&output_dir);
        let safe_name = target.replace("/", "_").replace("\\", "_");
        let out_path = format!("{}/forensic_image_{}.dd", output_dir, safe_name);

        let mut source = File::open(&target).map_err(|e| format!("Failed to open target: {e}"))?;
        let mut dest = File::create(&out_path).map_err(|e| format!("Failed to create image: {e}"))?;
        
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024 * 4]; // 4MB buffer for fast cloning
        let mut total_bytes = 0;

        // Clone the drive bit-for-bit
        while let Ok(n) = source.read(&mut buffer) {
            if n == 0 { break; }
            dest.write_all(&buffer[..n]).map_err(|e| e.to_string())?;
            hasher.update(&buffer[..n]);
            total_bytes += n as u64;
        }

        let hash_hex = format!("{:x}", hasher.finalize());
        
        let mut ledger = AuditLedger::init("logs/audit_chain.json");
        ledger.append("FORENSIC_CLONE", &target, &format!("Image SHA256: {}", hash_hex), "OPERATOR_ADMIN");

        Ok(CloneResult {
            image_path: out_path,
            bytes_copied: total_bytes,
            sha256_hash: hash_hex,
        })
    }).await.map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            run_file_recovery,
            run_drive_sanitization,
            run_file_sanitization,
            get_audit_trail,
            run_get_drive_info,
            run_hex_view,
            run_export_report,
            enumerate_drives,
            open_folder,
            run_forensic_clone
        ])
        .run(tauri::generate_context!())
        .expect("Error initializing Tauri execution runtime");
}
