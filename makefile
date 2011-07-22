# MinGW32 makefile for CMDkey.

CC = gcc
CFLAGS = -Wall -O2

%v.o: %.rc
	windres $< $@

all: edit.dll cmdkey.exe cmdkeynt.exe

edit.dll: edit.c editv.o
	$(CC) $(CFLAGS) $+ -mdll -s -o edit.dll -lcomdlg32 \
			-Wl,--out-implib,edit.a

cmdkey.exe: cmdkey.c cmdkeyv.o
	$(CC) $(CFLAGS) $+ -s -o cmdkey.exe edit.a

cmdkeynt.exe: cmdkey.c cmdkeyntv.o
	$(CC) $(CFLAGS) -DNT4 $+ -s -o cmdkeynt.exe edit.a

editv.o: edit.rc
cmdkeyv.o: cmdkey.rc
cmdkeyntv.o: cmdkey.rc
	windres -DNT4 $< $@
