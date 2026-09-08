# SIH26149: Digital Forensics & Data Sanitization Toolkit

This repository contains the complete implementation for the SIH26149 problem statement. It features a high-performance native Rust core engine and a lightweight Tauri v2 + React desktop interface.

## System Requirements
- OS: Linux (Ubuntu 22.04 recommended)
- RAM: Optimized for < 8GB environments
- Dependencies: `Node.js` (for Vite/React) and `Rust/Cargo` (for the native engine)

---

## 1. How to Run the Terminal Engine (Modules 1-3)
During development and for strict headless environments, you can run the core engine directly via the Rust CLI.

**Step 1: Set up the test drive fixture**
We use a dummy 64MB loopback file to simulate physical disks safely.
```bash
cd tests
chmod +x make_test_disk.sh
./make_test_disk.sh
cd ..
```
*(Note: If you run this script outside a sandbox, it requires `sudo` to mount the loopback and seed the JPEG/WAV files. You can just run it in your normal host terminal).*

**Step 2: Run the File Carver**
```bash
# Extract signatures from the target disk
cargo run -- recover tests/test_drive.raw
```
Check the `recovered/` directory for extracted artifacts.

**Step 3: Run the Hardware Sanitizer**
```bash
# Execute a DoD 5220.22-M 3-pass wipe
cargo run -- wipe tests/test_drive.raw dod-3pass
```
Check `reports/certificate.pdf` for the generated compliance certificate.

---

## 2. How to Run the GUI Desktop Application (Tauri v2)
The UI uses a Dual-Process architecture. The WebKitGTK render process communicates with the Rust core via a secure IPC bridge.

**Step 1: Install frontend dependencies**
```bash
cd gui
npm install
```

**Step 2: Launch in Development Mode**
From the `gui` folder, run the Tauri development server:
```bash
cd gui
npm run tauri dev
```
This will compile the Rust bindings and open the Tailwind CSS dashboard.

---

## 3. How to Build the Final Release Executable
For the final demonstration, you can compile the application into a standalone binary (AppImage or .deb) that requires zero dependencies to run.

```bash
cd gui
npm run tauri build
```
The compiled binaries will be placed in `src-tauri/target/release/bundle/`. 
*(Note: Compiling the release build invokes the heavy LLVM linker and will take several minutes to complete).*

---

## Security Guardrails
**CRITICAL:** The engine features a hardcoded Safety Guard (`src/engine/safety.rs`). 
If you attempt to run the CLI or the GUI targeting your host OS drive (e.g., `/dev/sda`, `/dev/nvme0n1`), the tool will immediately trigger a panic and abort execution to prevent accidental data destruction. Always use `tests/test_drive.raw` or verify your physical USB node using `lsblk` before execution.
