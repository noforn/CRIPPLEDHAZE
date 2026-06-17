CC64 = x86_64-w64-mingw32-gcc
LD64 = x86_64-w64-mingw32-ld
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
BEACON_INC = /SADDLEBACK/bofs/Extension-Kit/_include
CFLAGS = -I $(BEACON_INC) -I . -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -DBOF -c -D_WIN32_WINNT=0x0601

all: bof

bof: clean
	@(mkdir -p _bin 2>/dev/null) && echo 'creating _bin' || true
	@$(CC64) $(CFLAGS) jealousmonkey.c -o jealousmonkey.o
	@$(CC64) $(CFLAGS) appinfo64.c -o appinfo64.o
	@$(LD64) -r -o _bin/jealousmonkey.x64.o jealousmonkey.o appinfo64.o
	@$(STRIP64) _bin/jealousmonkey.x64.o
	@rm -f jealousmonkey.o appinfo64.o
	@echo '[+] _bin/jealousmonkey.x64.o'

clean:
	@rm -f jealousmonkey.o appinfo64.o
	@rm -rf _bin

.PHONY: all bof clean
