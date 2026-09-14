use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use sha2::{Digest, Sha256};
use serde::{Serialize, Deserialize};
use crate::engine::safety::SafetyGuard;

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB Window
pub const OVERLAP_SIZE: usize = 64 * 1024;      // 64 KB Boundary Guard

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CarvedArtifact {
    pub file_type: String,
    pub start_offset: u64,
    pub size_bytes: u64,
    pub output_path: String,
    pub sha256_checksum: String,
    pub is_fragmented_candidate: bool,
}

pub struct CarverEngine;

impl CarverEngine {
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut frequencies = [0usize; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }
        let len = data.len() as f64;
        frequencies.iter().fold(0.0, |acc, &count| {
            if count == 0 { acc }
            else {
                let p = count as f64 / len;
                acc - (p * p.log2())
            }
        })
    }

    pub fn scan_and_carve(target_path: &str, output_dir: &str) -> Result<Vec<CarvedArtifact>, String> {
        SafetyGuard::validate_target(target_path)?;
        std::fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;

        let mut file = File::open(target_path).map_err(|e| e.to_string())?;
        let total_size = file.metadata().map_err(|e| e.to_string())?.len();

        let mut artifacts = Vec::new();
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut current_disk_offset: u64 = 0;
        let mut artifact_counter = 0;

        while current_disk_offset < total_size {
            file.seek(SeekFrom::Start(current_disk_offset)).map_err(|e| e.to_string())?;
            let bytes_read = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if bytes_read == 0 { break; }

            let slice = &buffer[..bytes_read];

            // 1. Evaluate Entropy across current block
            let entropy = Self::calculate_entropy(&slice[..slice.len().min(4096)]);
            if entropy > 7.92 {
                println!("[!] Sector @ 0x{:X} shows High Entropy ({:.4}). Skipping encrypted container block.", current_disk_offset, entropy);
                current_disk_offset += bytes_read as u64;
                continue;
            }

            // 2. Parse Dynamic Formats (RIFF: WAV/AVI)
            let mut cursor = 0;
            while cursor + 8 <= slice.len() {
                if &slice[cursor..cursor + 4] == b"RIFF" {
                    let reported_size = u32::from_le_bytes([
                        slice[cursor + 4], slice[cursor + 5],
                        slice[cursor + 6], slice[cursor + 7]
                    ]) as u64;

                    let total_riff_len = reported_size + 8;
                    let absolute_start = current_disk_offset + cursor as u64;

                    if cursor as u64 + total_riff_len <= bytes_read as u64 {
                        let payload = &slice[cursor..cursor + total_riff_len as usize];
                        let out_name = format!("{}/carved_audio_{}.wav", output_dir, artifact_counter);
                        let hash = Self::persist_artifact(&out_name, payload)?;

                        artifacts.push(CarvedArtifact {
                            file_type: "WAV/RIFF".to_string(),
                            start_offset: absolute_start,
                            size_bytes: total_riff_len,
                            output_path: out_name,
                            sha256_checksum: hash,
                            is_fragmented_candidate: false,
                        });
                        artifact_counter += 1;
                        cursor += total_riff_len as usize;
                        continue;
                    }
                }
                cursor += 1;
            }

            // 3. Parse Static Formats (JPEG)
            let mut i = 0;
            while i + 3 <= slice.len() {
                if slice[i] == 0xFF && slice[i + 1] == 0xD8 && slice[i + 2] == 0xFF {
                    let absolute_start = current_disk_offset + i as u64;
                    // Scan forward for EOI marker (0xFF, 0xD9)
                    let mut eoi_index = None;
                    for j in (i + 2)..(slice.len() - 1) {
                        if slice[j] == 0xFF && slice[j + 1] == 0xD9 {
                            eoi_index = Some(j + 2);
                            break;
                        }
                    }

                    if let Some(end) = eoi_index {
                        let payload = &slice[i..end];
                        let out_name = format!("{}/carved_image_{}.jpg", output_dir, artifact_counter);
                        let hash = Self::persist_artifact(&out_name, payload)?;

                        artifacts.push(CarvedArtifact {
                            file_type: "JPEG".to_string(),
                            start_offset: absolute_start,
                            size_bytes: (end - i) as u64,
                            output_path: out_name,
                            sha256_checksum: hash,
                            is_fragmented_candidate: false,
                        });
                        artifact_counter += 1;
                        i = end;
                        continue;
                    } else {
                        // Bifragment / Cutoff candidate: Header found but no footer in 4MB window
                        artifacts.push(CarvedArtifact {
                            file_type: "JPEG (Fragmented/Truncated)".to_string(),
                            start_offset: absolute_start,
                            size_bytes: (slice.len() - i) as u64,
                            output_path: "NONE_TRUNCATED".to_string(),
                            sha256_checksum: "UNCOMPLETED_HASH".to_string(),
                            is_fragmented_candidate: true,
                        });
                    }
                }
                i += 1;
            }

            // 4. Parse PDF
            let mut i = 0;
            while i + 5 <= slice.len() {
                if &slice[i..i+5] == b"%PDF-" {
                    let absolute_start = current_disk_offset + i as u64;
                    let mut eof_index = None;
                    for j in (i + 5)..(slice.len() - 5) {
                        if &slice[j..j+5] == b"%%EOF" {
                            eof_index = Some(j + 5);
                            break;
                        }
                    }

                    if let Some(end) = eof_index {
                        let payload = &slice[i..end];
                        let out_name = format!("{}/carved_doc_{}.pdf", output_dir, artifact_counter);
                        let hash = Self::persist_artifact(&out_name, payload)?;

                        artifacts.push(CarvedArtifact {
                            file_type: "PDF Document".to_string(),
                            start_offset: absolute_start,
                            size_bytes: (end - i) as u64,
                            output_path: out_name,
                            sha256_checksum: hash,
                            is_fragmented_candidate: false,
                        });
                        artifact_counter += 1;
                        i = end;
                        continue;
                    }
                }
                i += 1;
            }

            // ZIP and DOCX Parsing
            let mut i = 0;
            while i + 4 <= slice.len() {
                if &slice[i..i+4] == b"PK\x03\x04" {
                    let absolute_start = current_disk_offset + i as u64;
                    let mut eof_index = None;
                    for j in (i + 4)..(slice.len() - 22) {
                        if &slice[j..j+4] == b"PK\x05\x06" {
                            eof_index = Some(j + 22);
                            break;
                        }
                    }
                    let end = eof_index.unwrap_or_else(|| (i + 5 * 1024 * 1024).min(slice.len()));
                    let payload = &slice[i..end];
                    let out_name = format!("{}/carved_archive_or_doc_{}.zip", output_dir, artifact_counter);
                    let hash = Self::persist_artifact(&out_name, payload).unwrap_or_else(|_| "HASH_ERROR".to_string());

                    artifacts.push(CarvedArtifact {
                        file_type: "ZIP / DOCX / XLSX".to_string(),
                        start_offset: absolute_start,
                        size_bytes: (end - i) as u64,
                        output_path: out_name,
                        sha256_checksum: hash,
                        is_fragmented_candidate: eof_index.is_none(),
                    });
                    artifact_counter += 1;
                    i = end;
                    continue;
                }
                i += 1;
            }

            // PNG Parsing
            let mut i = 0;
            while i + 8 <= slice.len() {
                if &slice[i..i+8] == b"\x89PNG\r\n\x1a\n" {
                    let absolute_start = current_disk_offset + i as u64;
                    let mut eoi_index = None;
                    for j in (i + 8)..(slice.len() - 8) {
                        if &slice[j..j+8] == b"IEND\xaeB\x60\x82" {
                            eoi_index = Some(j + 8);
                            break;
                        }
                    }

                    if let Some(end) = eoi_index {
                        let payload = &slice[i..end];
                        let out_name = format!("{}/carved_image_{}.png", output_dir, artifact_counter);
                        let hash = Self::persist_artifact(&out_name, payload).unwrap_or_else(|_| "HASH_ERROR".to_string());

                        artifacts.push(CarvedArtifact {
                            file_type: "PNG Image".to_string(),
                            start_offset: absolute_start,
                            size_bytes: (end - i) as u64,
                            output_path: out_name,
                            sha256_checksum: hash,
                            is_fragmented_candidate: false,
                        });
                        artifact_counter += 1;
                        i = end;
                        continue;
                    }
                }
                i += 1;
            }

            // 5. Parse MP4 Video (Basic Header Carve)
            let mut i = 0;
            while i + 8 <= slice.len() {
                if &slice[i+4..i+8] == b"ftyp" {
                    let absolute_start = current_disk_offset + i as u64;
                    // MP4 parsing requires atom tree traversal. For prototype, we carve a 2MB chunk
                    // or to the end of the buffer, marking it as fragmented.
                    let end = (i + 2 * 1024 * 1024).min(slice.len());
                    let payload = &slice[i..end];
                    let out_name = format!("{}/carved_video_{}.mp4", output_dir, artifact_counter);
                    let hash = Self::persist_artifact(&out_name, payload)?;

                    artifacts.push(CarvedArtifact {
                        file_type: "MP4 Video".to_string(),
                        start_offset: absolute_start,
                        size_bytes: (end - i) as u64,
                        output_path: out_name,
                        sha256_checksum: hash,
                        is_fragmented_candidate: true, // Marked as fragmented due to arbitrary chunking
                    });
                    artifact_counter += 1;
                    i = end;
                    continue;
                }
                i += 1;
            }

            // Slide window forward with overlap boundary protection
            if bytes_read == CHUNK_SIZE {
                current_disk_offset += (CHUNK_SIZE - OVERLAP_SIZE) as u64;
            } else {
                break;
            }
        }

        Ok(artifacts)
    }

    fn persist_artifact(path: &str, data: &[u8]) -> Result<String, String> {
        let mut out = File::create(path).map_err(|e| e.to_string())?;
        out.write_all(data).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let hash_hex = result.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        Ok(hash_hex)
    }
}
