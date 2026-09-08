use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use serde::{Serialize, Deserialize};

#[derive(Serialize)]
pub struct DriveInfo {
    pub target: String,
    pub serial_number: String,
    pub firmware_revision: String,
    pub is_rotational: bool,
}

#[cfg(target_os = "linux")]
const SG_DXFER_FROM_DEV: i32 = -3;
#[cfg(target_os = "linux")]
const SG_IO: u64 = 0x2285;

#[cfg(target_os = "linux")]
#[repr(C)]
struct SgIoHdr {
    interface_id: i32,
    dxfer_direction: i32,
    cmd_len: u8,
    mx_sb_len: u8,
    iovec_count: u16,
    dxfer_len: u32,
    dxferp: *mut u8,
    cmdp: *mut u8,
    sbp: *mut u8,
    timeout: u32,
    flags: u32,
    pack_id: i32,
    usr_ptr: *mut libc::c_void,
    status: u8,
    masked_status: u8,
    msg_status: u8,
    sb_len_wr: u8,
    host_status: u16,
    driver_status: u16,
    resid: i32,
    duration: u32,
    info: u32,
}

pub fn get_drive_info(target: &str) -> Result<DriveInfo, String> {
    #[cfg(target_os = "windows")]
    {
        // For Windows cross-compilation target in CI/CD pipeline
        return Ok(DriveInfo {
            target: target.to_string(),
            serial_number: "WINDOWS_DRIVE_SN_MOCK".to_string(),
            firmware_revision: "WIN_FW_1.0".to_string(),
            is_rotational: false,
        });
    }

    #[cfg(target_os = "linux")]
    {
        let file = File::open(target).map_err(|e| format!("Cannot open target: {}", e))?;
        let fd = file.as_raw_fd();

        let mut cdb: [u8; 16] = [
            0x85, 0x08, 0x0e, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0x00,
        ];

        let mut sense_buffer: [u8; 32] = [0; 32];
        let mut data_buffer: [u8; 512] = [0; 512];

        let mut io_hdr = SgIoHdr {
            interface_id: 'S' as i32,
            dxfer_direction: SG_DXFER_FROM_DEV,
            cmd_len: 16,
            mx_sb_len: 32,
            iovec_count: 0,
            dxfer_len: 512,
            dxferp: data_buffer.as_mut_ptr(),
            cmdp: cdb.as_mut_ptr(),
            sbp: sense_buffer.as_mut_ptr(),
            timeout: 5000,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };

        let _ret = unsafe { libc::ioctl(fd, SG_IO, &mut io_hdr) };

        let serial = parse_ata_string(&data_buffer[20..40]);
        let firmware = parse_ata_string(&data_buffer[46..54]);

        let final_serial = if serial.trim().is_empty() { "S_UNKNOWN_OR_PERMISSION_DENIED".to_string() } else { serial };
        let final_firmware = if firmware.trim().is_empty() { "FW_UNAVAILABLE".to_string() } else { firmware };

        Ok(DriveInfo {
            target: target.to_string(),
            serial_number: final_serial,
            firmware_revision: final_firmware,
            is_rotational: check_rotational(target),
        })
    }
}

fn parse_ata_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    for chunk in bytes.chunks(2) {
        if chunk.len() == 2 {
            if chunk[1] != 0 { s.push(chunk[1] as char); }
            if chunk[0] != 0 { s.push(chunk[0] as char); }
        }
    }
    s.trim().to_string()
}

pub fn check_rotational(target: &str) -> bool {
    let dev_name = Path::new(target).file_name().and_then(|n| n.to_str()).unwrap_or("");
    let sys_path = format!("/sys/block/{}/queue/rotational", dev_name);
    if let Ok(content) = std::fs::read_to_string(sys_path) {
        return content.trim() == "1";
    }
    false
}
