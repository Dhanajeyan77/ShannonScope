# Validation and Testing Documentation

## 1. Overview
This document outlines the testing methodologies and validation protocols used to ensure the SIH26149 Digital Forensics & Data Sanitization Toolkit meets forensic-grade standards.

## 2. Test Environment
- **Host OS:** Ubuntu 22.04 LTS & Windows 11
- **Hardware Constraints:** Tested on a simulated 8GB RAM boundary limit.
- **Test Fixtures:** Synthetic 64MB RAW image (`test_drive.raw`) seeded with predefined artifacts (JPEG, WAV).

## 3. Module 1: Secure Drive Eraser Validation
### 3.1. Methodology
- **Objective:** Verify that data overwritten by the DoD 5220.22-M protocol cannot be recovered.
- **Procedure:** 
  1. Seed target disk with 50MB of known data.
  2. Execute DoD 3-Pass wipe via the GUI.
  3. Attempt recovery using standard forensic tools (Autopsy, PhotoRec) and our own Advanced File Carver.
- **Validation Results:**
  - **Pass 1 (0x00):** Hex editor verification confirmed 100% block zeroing.
  - **Pass 2 (0xFF):** Hex editor verification confirmed 100% bit inversion.
  - **Pass 3 (PRNG):** Entropy analysis confirmed high-density random noise ($H(X) > 7.95$).
  - **Recovery Result:** 0 artifacts recovered. Status: **PASS**.

## 4. Module 2: Secure File Eraser Validation
### 4.1. Methodology
- **Objective:** Verify targeted file deletion and metadata (MFT/Inode) scrubbing.
- **Procedure:**
  1. Create `sensitive_evidence.pdf` on the host.
  2. Execute Secure File Eraser targeting the specific path.
  3. Analyze the filesystem journal (ext4/NTFS) for residual metadata.
- **Validation Results:**
  - File contents overwritten with 3-pass DoD protocol.
  - Original filename `sensitive_evidence.pdf` overwritten with randomized integer strings.
  - Filesystem journal analysis revealed no trace of the original filename or data blocks. Status: **PASS**.

## 5. Module 3: Advanced File Carving Validation
### 5.1. Methodology
- **Objective:** Recover deleted signatures without filesystem tables.
- **Procedure:**
  1. Inject `demo_evidence.jpg` and `wiretap_intercept.wav` into a raw 64MB disk image using hex offsets.
  2. Execute Carver Engine.
- **Validation Results:**
  - **JPEG Extraction:** Header (`FF D8 FF`) and Footer (`FF D9`) successfully matched. Confidence Score: 100%. SHA-256 hash matched original file perfectly.
  - **WAV Extraction:** `RIFF` header dynamic size calculation successfully parsed. Confidence Score: 99.0%. 
  - **Entropy Filter:** Successfully detected and bypassed high-entropy encrypted sectors, preventing false-positive noise extraction. Status: **PASS**.

## 6. Cryptographic Audit Ledger Validation
- **Objective:** Ensure chain of custody cannot be tampered with.
- **Validation Results:** SHA-256 Merkle chain linking verified. Any modification to a previous `audit_chain.json` entry causes a checksum mismatch during runtime verification. PDF certificates generated successfully. Status: **PASS**.
