# MinGW32/TDM64 makefile for CMDread.

CC = gcc
CFLAGS = -Wall -O2

%_x86.o: %.c
	$(CC) -m32 -c $(CFLAGS) $< -o $@

%v_x86.o: %.rc
	windres -U _WIN64 -F pe-i386 $< $@

%_x86.exe: %_x86.o %v_x86.o
	$(CC) -m32 $+ edit_x86.a -s -o $@

%_amd64.o: %.c
	$(CC) -m64 -c $(CFLAGS) $< -o $@

%v_amd64.o: %.rc
	windres -F pe-x86-64 $< $@

%_amd64.exe: %_amd64.o %v_amd64.o
	$(CC) -m64 $+ edit_amd64.a -s -o $@

all:	   CMDread32	  CMDread64
CMDread32: edit_x86.dll   CMDread_x86.exe
CMDread64: edit_amd64.dll CMDread_amd64.exe

edit_x86.dll: edit_x86.o editv_x86.o
	$(CC) -m32 $+ -mdll -s -o $@ -lcomdlg32 -Wl,-shared,--out-implib,$(basename $@).a,--image-base,0xCE00000

edit_amd64.dll: edit_amd64.o editv_amd64.o
	$(CC) -m64 $+ -mdll -s -o $@ -lcomdlg32 -Wl,-shared,--out-implib,$(basename $@).a,--image-base,0xCE000000

edit_x86.o    edit_amd64.o:    edit.c	 CMDread.h version.h
CMDread_x86.o CMDread_amd64.o: CMDread.c CMDread.h version.h

editv_x86.o    editv_amd64.o:	 edit.rc    version.h
CMDreadv_x86.o CMDreadv_amd64.o: CMDread.rc version.h

clean:
	-cmd /c "del *.o *.a 2>nul"
