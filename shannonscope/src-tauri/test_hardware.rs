use std::fs::File;
use std::os::unix::io::AsRawFd;

fn main() {
    let target = "/dev/sda1";
    let parent_target = target.trim_end_matches(|c: char| c.is_ascii_digit());
    println!("Trying to open: {}", parent_target);
    match File::open(parent_target) {
        Ok(file) => println!("Opened successfully! FD: {}", file.as_raw_fd()),
        Err(e) => println!("Error opening: {}", e),
    }
}
