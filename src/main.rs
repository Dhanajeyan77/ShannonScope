mod engine;

use engine::safety::SafetyGuard;
use engine::carver::CarverEngine;
use engine::sanitizer::{SanitizerEngine, WipeProfile};
use engine::audit::AuditLedger;
use std::env;

fn print_usage(program: &str) {
    println!("Usage: {} <recover|wipe> <target_path> [profile]", program);
    println!("  Profiles for wipe: nist-clear, hardware-purge, dod-3pass");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        print_usage(&args[0]);
        return;
    }

    let mode = &args[1];
    let target = &args[2];

    println!("Validating target: {}", target);
    if let Err(e) = SafetyGuard::validate_target(target) {
        println!("Error: {}", e);
        return;
    }

    let mut ledger = AuditLedger::init("logs/audit_chain.json");

    if mode == "recover" {
        println!("Starting carver on target...");
        let output_dir = "recovered";
        let _ = std::fs::remove_dir_all(output_dir);

        match CarverEngine::scan_and_carve(target, output_dir) {
            Ok(artifacts) => {
                println!("Carving complete. Found {} artifacts:", artifacts.len());
                for art in &artifacts {
                    println!(" - [{}] Offset: 0x{:X}, Size: {} bytes, Hash: {}, Output: {}", 
                        art.file_type, art.start_offset, art.size_bytes, art.sha256_checksum, art.output_path);
                }
                let entry = ledger.append("CARVE", target, "SUCCESS", "OPERATOR_ADMIN");
                println!("Logged audit entry: {}", entry.record_hash);
            },
            Err(e) => {
                println!("Carving failed: {}", e);
                ledger.append("CARVE", target, &format!("FAILED: {}", e), "OPERATOR_ADMIN");
            }
        }
    } else if mode == "wipe" {
        let profile_str = if args.len() > 3 { args[3].as_str() } else { "nist-clear" };
        let profile = match profile_str {
            "nist-clear" => WipeProfile::NistClear,
            "hardware-purge" => WipeProfile::HardwarePurge,
            "dod-3pass" => WipeProfile::Dod522022M,
            _ => {
                println!("Invalid wipe profile.");
                return;
            }
        };

        match SanitizerEngine::sanitize_target(target, profile) {
            Ok(clean) => {
                let status = if clean { "VERIFIED_CLEAN" } else { "VERIFICATION_FAILED" };
                println!("Wipe complete. Status: {}", status);
                let entry = ledger.append("WIPE", target, status, "OPERATOR_ADMIN");
                
                std::fs::create_dir_all("reports").unwrap();
                if let Err(e) = ledger.generate_pdf_certificate(ledger.entries.len() - 1, "reports/certificate.pdf") {
                    println!("Warning: Failed to generate certificate: {}", e);
                } else {
                    println!("Certificate generated at reports/certificate.pdf");
                }
            },
            Err(e) => {
                println!("Wipe failed: {}", e);
                ledger.append("WIPE", target, &format!("FAILED: {}", e), "OPERATOR_ADMIN");
            }
        }
    } else {
        print_usage(&args[0]);
    }
}
