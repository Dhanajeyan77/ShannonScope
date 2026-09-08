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

#[tauri::command]
fn run_list_drives() -> Vec<String> {
    use sysinfo::Disks;
    let mut drives = Vec::new();
    
    // Add logical partitions using sysinfo
    let disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        if let Some(path) = disk.mount_point().to_str() {
            // For windows it's "C:\", for Linux it's "/mnt/..."
            let name = format!("{} ({} GB)", path, disk.total_space() / 1_000_000_000);
            drives.push(name);
        }
    }

    // Add physical raw paths manually for forensic carving
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/block/") {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("sd") || name.starts_with("nvme") {
                    drives.push(format!("/dev/{}", name));
                }
            }
        }
        drives.push("tests/test_drive.raw".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        drives.push(r"\\.\PhysicalDrive0".to_string());
        drives.push(r"\\.\PhysicalDrive1".to_string());
        drives.push(r"\\.\PhysicalDrive2".to_string());
    }

    drives
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
            run_list_drives
        ])
        .run(tauri::generate_context!())
        .expect("Error initializing Tauri execution runtime");
}
