fn main() {
    let target = "/dev/sda1";
    let parent_target = target.trim_end_matches(|c: char| c.is_ascii_digit());
    println!("Target: {}, Parent: {}", target, parent_target);
}
