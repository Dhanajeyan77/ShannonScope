use std::fs::File;
fn main() {
    let f = File::open("/dev/sda").unwrap();
    println!("Len: {}", f.metadata().unwrap().len());
}
