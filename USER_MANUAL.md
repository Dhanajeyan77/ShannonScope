# Operator User Manual

## 1. Introduction
Welcome to the SIH26149 Integrated Digital Forensics & Data Sanitization Toolkit. This software provides law enforcement, enterprises, and IT administrators with a unified environment for recovering deleted evidence and securely sanitizing classified drives.

## 2. Launching the Software
Depending on your installation:
- **Windows:** Double click `SIH26149-Toolkit.exe`.
- **Ubuntu/Linux:** Execute `./SIH26149-Toolkit.AppImage` or launch from your desktop environment.
- **Development Source:** Run `cd gui && npm run tauri dev`.

## 3. Dashboard Overview
The main interface is divided into three primary panels:
1. **Execution Directives:** Where you input targets and issue commands.
2. **Cryptographic Audit Ledger:** A real-time, tamper-proof log of all operations performed in the current session.
3. **Carved File Gallery:** A visual gallery displaying recovered forensic artifacts, confidence scores, and cryptographic hashes.

---

## 4. How to Use the Advanced File Carver (Recovery)
1. Locate the **Target Disk / Image Path** input box.
2. Enter the path to your target drive. 
   - *Example (Linux Physical USB):* `/dev/sdc`
   - *Example (Windows Physical Drive):* `\\.\PhysicalDrive1`
   - *Example (Disk Image):* `tests/test_drive.raw`
3. Click **Start Recovery**.
4. The engine will scan the raw sectors. Recovered files (JPEGs, MP4s, PDFs, WAVs) will automatically populate in the **Carved File Gallery**.
5. Check the `recovered/` folder on your host machine to view the actual extracted files.

---

## 5. How to Use the Secure Drive Eraser
**WARNING:** This action is irreversible. All data will be permanently destroyed.
1. Locate the **Target Disk / Image Path** input box and enter your drive path.
2. Select your desired **Sanitization Profile** from the dropdown:
   - *NIST 800-88 Clear:* Fast, 1-pass zeroes.
   - *DoD 5220.22-M:* Slower, military-grade 3-pass overwrite.
   - *Hardware Purge:* Instantly signals SSD firmware to drop blocks (NVMe/SSD only).
3. Click **Sanitize Drive**.
4. Wait for the success confirmation in the terminal/UI log. A PDF Certificate of Destruction will be generated in the `reports/` folder.

---

## 6. How to Use the Secure File Eraser (Targeted Deletion)
1. Locate the **Target File Path** input box.
2. Enter the absolute path to the highly sensitive file you wish to destroy (e.g., `/home/user/classified_report.pdf`).
3. Select your Sanitization Profile.
4. Click **Secure File Eraser**.
5. The software will overwrite the data, mathematically scrub the filesystem metadata (MFT/Inodes), and unlink the file permanently.

---

## 7. Audit and Compliance
All operations are automatically logged into `logs/audit_chain.json`. This ledger uses a SHA-256 Merkle chain. If any investigator alters a previous log entry, the entire cryptographic chain breaks, ensuring 100% court-admissible evidence integrity.
