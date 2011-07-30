# MinGW32 makefile for CMDkey.

CC = gcc
CFLAGS = -Wall -O2

%v.o: %.rc
	windres $< $@

%.exe: %.o %v.o
	$(CC) $+ edit.a -s -o $@

all: edit.dll cmdkey.exe

edit.dll: edit.o editv.o
	$(CC) $+ -mdll -s -o $@ -lcomdlg32 -Wl,--out-implib,$(basename $@).a

edit.o: edit.c cmdkey.h version.h
cmdkey.o: cmdkey.c cmdkey.h version.h

editv.o: edit.rc version.h
cmdkeyv.o: cmdkey.rc version.h
