# MinGW32 makefile for CMDkey.

CC = gcc
CFLAGS = -Wall -O2

%v.o: %.rc
	windres $< $@

%.exe: %.o %v.o
	$(CC) $(CFLAGS) $+ edit.a -s -o $@

all: edit.dll cmdkey.exe cmdkeynt.exe

edit.dll: edit.o editv.o
	$(CC) $(CFLAGS) $+ -mdll -s -o $@ -lcomdlg32 -Wl,--out-implib,$(basename $@).a

cmdkey.o: cmdkey.c
cmdkeynt.o: cmdkey.c
	$(CC) $(CFLAGS) -DNT4 -c $< -o $@

editv.o: edit.rc
cmdkeyv.o: cmdkey.rc

cmdkeyntv.o: cmdkey.rc
	windres -DNT4 $< $@
