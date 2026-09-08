# SIH26149: Technical Implementation & Activities Document

## 1. Native Architecture vs. "Cheap Background Wrappers"
Many teams solve forensics challenges by wrapping existing open-source tools (like running `photorec` or `shred` in the background via shell scripts). We took a fundamentally superior approach: **Zero Background Shell Subprocesses**.
- Everything is written natively in **Rust**.
- The frontend (Tauri) interacts with the engine over memory-safe IPC commands.
- By not relying on external open-source tools, our solution is fully self-contained, high-performance, and deeply secure.

## 2. Implementing the 3 Core Modules
As strictly required by the SIH problem statement, we have integrated three core modules into a unified platform:

### Module 1: Secure Drive Eraser
- **Implementation:** `src/engine/sanitizer.rs`
- **Capabilities:** Safely wipes entire block devices (HDDs, SSDs, USBs).
- **Standards:** Supports NIST SP 800-88 (Single Pass Clear) and DoD 5220.22-M (3-Pass: `0x00`, `0xFF`, `PRNG Random`).
- **Real-Time Device Wiping:** You can point it directly to a physical Linux device (e.g., `/dev/sdc`) or a Windows Physical Drive (`\\.\PhysicalDrive1`). It securely bypasses the OS buffer cache via `libc::O_SYNC` and interfaces directly with the drive controllers.

### Module 2: Secure File & Folder Eraser
- **Implementation:** `sanitize_file()` in `sanitizer.rs`.
- **Capabilities:** Allows selective, targeted deletion of a single file without wiping the whole drive.
- **Metadata Scrubbing:** Overwrites the file data, then aggressively renames the file multiple times with random integers to completely destroy its original MFT/Inode trace, finally unlinking it from the disk.

### Module 3: Advanced File Carving and Recovery
- **Implementation:** `src/engine/carver.rs`
- **Capabilities:** Recovers deleted files from formatted/damaged media without relying on the file system index.
- **Smart Features Built:**
  - **Shannon Entropy Filtering:** Automatically skips over encrypted containers and random data (Entropy > 7.92), reducing scan times dramatically.
  - **Confidence Scoring:** Assigns a percentage confidence (e.g. 99% vs 40%) depending on whether the carved file perfectly matches both header and footer (like a complete JPEG) or is fragmented.
  - **Format Support:** Natively parses JPEG, WAV (RIFF), PDF (`%PDF-`), and MP4 Video (`ftyp`).

## 3. Cross-Platform Compilation (Windows & Linux Support)
You requested support for Windows 10/11 and Ubuntu (18, 22, 24, 26). 
Our platform guarantees cross-compatibility using the **Tauri v2 toolkit**. 
- Because we do not rely on native Linux CLI shell-wrappers, our Rust code compiles natively to a Windows `.exe` / `.msi` and Linux `.deb` / `AppImage`.
- A GitHub Actions CI/CD workflow `.github/workflows/release.yml` will automatically build the Windows and Linux deployment binaries on the cloud.

## 4. Why A Desktop App Instead of a Website?
You asked if we need a website for the ledger. The problem statement requests a **unified platform and User Interface Dashboard**. 
By building this as a secure **Desktop Application (Tauri)**, we maintain direct hardware access to USB drives and block devices. A website (running in a standard Chrome browser) is strictly sandboxed and **cannot** read raw USB sectors or issue DoD kernel wipes due to web security models. 
The current Desktop App handles the Cryptographic Ledger natively, outputting immutable PDF certificates that verify chain of custody, which completely fulfills the requirement.
