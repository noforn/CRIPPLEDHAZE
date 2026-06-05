#ifndef INDIRECT_H
#define INDIRECT_H

#include <windows.h>

typedef long NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define HASH_NtCreateFile 0x03888f9dU
#define HASH_NtWriteFile 0x680e1933U
#define HASH_NtClose 0xdcd44c5fU
#define HASH_NtQueryVirtualMemory 0x4f138492U

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    void *Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  void *SecurityDescriptor;
  void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define OBJ_CASE_INSENSITIVE 0x00000040L

#define FILE_SUPERSEDE 0x00000000
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005

#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

#define FILE_ATTRIBUTE_NORMAL 0x00000080

extern volatile DWORD g_ssn;
extern void *g_syscall_gadget;

void do_indirect_syscall(void);

int indirect_init(HMODULE hNtdll);

BOOL io_create_directory_a(const char *path);
HANDLE io_create_file_a(const char *path, DWORD access, DWORD disposition);
BOOL io_write_file(HANDLE h, const void *buf, DWORD len, DWORD *written);
BOOL io_close_handle(HANDLE h);
SIZE_T io_virtual_query(LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len);

#endif
