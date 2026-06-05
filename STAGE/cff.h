#ifndef CFF_H
#define CFF_H

#include <windows.h>

#define CFF_DONE 99

typedef struct {
  unsigned char *enc;
  int len;
} CFF_ENC;

typedef DWORD(WINAPI *cff_expand_fn)(LPCSTR, LPSTR, DWORD);
typedef BOOL(WINAPI *cff_mkdir_fn)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef HANDLE(WINAPI *cff_create_fn)(LPCSTR, DWORD, DWORD,
                                       LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                       HANDLE);
typedef BOOL(WINAPI *cff_write_fn)(HANDLE, LPCVOID, DWORD, LPDWORD,
                                   LPOVERLAPPED);
typedef BOOL(WINAPI *cff_close_fn)(HANDLE);

typedef struct {
  int use_indirect;
  cff_expand_fn expand;
  cff_mkdir_fn mkdir;
  cff_create_fn create;
  cff_write_fn write;
  cff_close_fn close;
} CFF_IO;

void dc_xd(unsigned char *enc, char *out, int len);
void dc_xb(unsigned char *enc, unsigned char *out, int len, int abs_offset);
void dc_path_expand(char *path, int cap, cff_expand_fn expand);

int cff_step(int cur, int nxt, volatile ULONG64 *acc);

void cff_sys_dirs(CFF_ENC *dirs, int count, char *buf, int cap, CFF_IO *io,
                  volatile ULONG64 *acc);

void cff_dll_dirs(CFF_ENC *dirs, int count, char *buf, int cap, CFF_IO *io,
                  volatile ULONG64 *acc);

void cff_write_payload(const char *path, unsigned char *blob, int blob_len,
                       CFF_IO *io, volatile ULONG64 *acc);

#endif
