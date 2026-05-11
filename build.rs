fn main() {
    // Rebuild whenever the encrypted payload changes (or appears for the first time).
    println!("cargo:rerun-if-changed=sc_enc.bin");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = std::path::Path::new(&out_dir).join("shellcode.rs");

    let bytes = std::fs::read("sc_enc.bin").unwrap_or_default();

    // Emit a const byte-array literal that borrow.rs includes at compile time.
    let mut s = String::from("pub const SHELLCODE_ENC: &[u8] = &[");
    for b in &bytes {
        s.push_str(&format!("0x{b:02x},"));
    }
    s.push_str("];");

    std::fs::write(&out_path, s).expect("failed to write shellcode.rs");
}
