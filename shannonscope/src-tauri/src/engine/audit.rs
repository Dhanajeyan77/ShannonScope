use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, BufWriter};
use std::path::Path;
use printpdf::*;

use crate::engine::types::AuditEntry;

pub struct AuditLedger {
    pub file_path: String,
    pub entries: Vec<AuditEntry>,
}

impl AuditLedger {
    pub fn init(path: &str) -> Self {
        let mut entries = Vec::new();
        if Path::new(path).exists() {
            if let Ok(mut file) = File::open(path) {
                let mut content = String::new();
                if file.read_to_string(&mut content).is_ok() {
                    if let Ok(parsed) = serde_json::from_str(&content) {
                        entries = parsed;
                    }
                }
            }
        }
        Self {
            file_path: path.to_string(),
            entries,
        }
    }

    pub fn append(&mut self, action: &str, target: &str, status: &str, operator: &str) -> AuditEntry {
        let prev_hash = if let Some(last) = self.entries.last() {
            last.record_hash.clone()
        } else {
            "GENESIS_BLOCK".to_string()
        };

        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let payload = format!("{}_{}_{}_{}_{}_{}", self.entries.len(), timestamp, action, target, status, prev_hash);
        
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let record_hash = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let entry = AuditEntry {
            index: self.entries.len(),
            timestamp,
            action: action.to_string(),
            target: target.to_string(),
            status: status.to_string(),
            operator_id: operator.to_string(),
            previous_hash: prev_hash,
            record_hash,
        };

        self.entries.push(entry.clone());
        self.save_to_disk();
        entry
    }

    fn save_to_disk(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.entries) {
            if let Ok(mut file) = OpenOptions::new().write(true).create(true).truncate(true).open(&self.file_path) {
                let _ = file.write_all(json.as_bytes());
            }
        }
    }

    pub fn verify_chain(&self) -> bool {
        let mut expected_prev_hash = "GENESIS_BLOCK".to_string();
        for entry in &self.entries {
            if entry.previous_hash != expected_prev_hash {
                return false; // Chain broken
            }
            let payload = format!("{}_{}_{}_{}_{}_{}", entry.index, entry.timestamp, entry.action, entry.target, entry.status, entry.previous_hash);
            let mut hasher = Sha256::new();
            hasher.update(payload.as_bytes());
            let computed_hash = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
            
            if entry.record_hash != computed_hash {
                return false; // Record tampered
            }
            expected_prev_hash = entry.record_hash.clone();
        }
        true
    }

    pub fn generate_pdf_certificate(&self, out_path: &str) -> Result<(), String> {
        let (doc, page1, layer1) = PdfDocument::new("Sanitization Certificate", Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page1).get_layer(layer1);
        let font = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;

        current_layer.use_text("CERTIFICATE OF DATA DESTRUCTION", 24.0, Mm(30.0), Mm(270.0), &font);
        
        // Add verifiable chain indicator
        let chain_status = if self.verify_chain() { "VERIFIED INTACT" } else { "TAMPERED / BROKEN" };
        current_layer.use_text(format!("Merkle Chain Integrity: {}", chain_status), 12.0, Mm(30.0), Mm(250.0), &font);

        let mut y = 230.0;
        for entry in &self.entries {
            if y < 30.0 { break; }
            let text = format!("[{}] {} -> {}", entry.action, entry.target, entry.status);
            current_layer.use_text(text, 10.0, Mm(30.0), Mm(y), &font);
            y -= 10.0;
        }

        let file = File::create(out_path).map_err(|e| e.to_string())?;
        doc.save(&mut BufWriter::new(file)).map_err(|e| e.to_string())?;
        Ok(())
    }
}
