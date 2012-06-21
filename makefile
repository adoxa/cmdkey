# MinGW32/TDM64 makefile for CMDkey.

CC = gcc
CFLAGS = -Wall -O2

x86/%.o: %.c
	$(CC) -m32 -c $(CFLAGS) $< -o $@

x86/%v.o: %.rc
	windres -F pe-i386 $< $@

x86/%.exe: x86/%.o x86/%v.o
	$(CC) -m32 $+ x86/edit.a -s -o $@

x64/%.o: %.c
	$(CC) -m64 -c $(CFLAGS) $< -o $@

x64/%v.o: %.rc
	windres -F pe-x86-64 $< $@

x64/%.exe: x64/%.o x64/%v.o
	$(CC) -m64 $+ x64/edit.a -s -o $@

all: cmdkey32 cmdkey64
cmdkey32: x86 x86/edit.dll x86/cmdkey.exe
cmdkey64: x64 x64/edit.dll x64/cmdkey.exe

x86 x64:
	cmd /c "mkdir $@"

x86/edit.dll: x86/edit.o x86/editv.o
	$(CC) -m32 $+ -mdll -s -o $@ -lcomdlg32 -Wl,--out-implib,$(basename $@).a

x64/edit.dll: x64/edit.o x64/editv.o
	$(CC) -m64 $+ -mdll -s -o $@ -lcomdlg32 -Wl,--out-implib,$(basename $@).a

x86/edit.o x64/edit.o: edit.c cmdkey.h version.h
x86/cmdkey.o x64/cmdkey.o: cmdkey.c cmdkey.h version.h

x86/editv.o x64/editv.o: edit.rc version.h
x86/cmdkeyv.o x64/cmdkeyv.o: cmdkey.rc version.h

# Need two commands, because if the directory doesn't exist, it won't delete
# anything at all.
clean:
	-cmd /c "del x86\*.o 2>nul"
	-cmd /c "del x64\*.o 2>nul"
